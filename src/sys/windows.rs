// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b:240716507): There is huge chunk for code which depends on haxm, whpx or gvm to be enabled but
// isn't marked so. Remove this when we do so.
#![allow(dead_code, unused_imports, unused_variables, unreachable_code)]

pub(crate) mod control_server;
pub(crate) mod irq_wait;
pub(crate) mod main;
#[cfg(not(feature = "crash-report"))]
mod panic_hook;

mod generic;
use generic as product;
pub(crate) mod run_vcpu;

#[cfg(feature = "whpx")]
use std::arch::x86_64::__cpuid;
#[cfg(feature = "whpx")]
use std::arch::x86_64::__cpuid_count;
use std::cmp::Reverse;
#[cfg(feature = "gpu")]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::stdin;
use std::iter;
use std::mem;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use arch::CpuConfigArch;
use arch::IrqChipArch;
use arch::LinuxArch;
use arch::RunnableLinuxVm;
use arch::VcpuArch;
use arch::VirtioDeviceStub;
use arch::VmArch;
use arch::VmComponents;
use arch::VmImage;
use base::enable_high_res_timers;
use base::error;
use base::info;
use base::open_file;
use base::warn;
#[cfg(feature = "gpu")]
use base::BlockingMode;
use base::CloseNotifier;
use base::Event;
use base::EventToken;
use base::EventType;
use base::FlushOnDropTube;
#[cfg(feature = "gpu")]
use base::FramingMode;
use base::FromRawDescriptor;
use base::ProtoTube;
use base::RawDescriptor;
use base::ReadNotifier;
use base::RecvTube;
use base::SendTube;
#[cfg(feature = "gpu")]
use base::StreamChannel;
use base::Terminal;
use base::TriggeredEvent;
use base::Tube;
use base::TubeError;
use base::VmEventType;
use base::WaitContext;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use control_server::ControlServer;
use crosvm_cli::sys::windows::exit::Exit;
use crosvm_cli::sys::windows::exit::ExitContext;
use crosvm_cli::sys::windows::exit::ExitContextAnyhow;
use crosvm_cli::sys::windows::exit::ExitContextOption;
use devices::create_devices_worker_thread;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::tsc::get_tsc_sync_mitigations;
use devices::tsc::standard_deviation;
use devices::tsc::TscSyncMitigations;
use devices::virtio;
use devices::virtio::block::DiskOption;
#[cfg(feature = "audio")]
use devices::virtio::snd::common_backend::VirtioSnd;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuVmmConfig;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::gpu::sys::windows::product::GpuBackendConfig as GpuBackendConfigProduct;
#[cfg(feature = "audio")]
use devices::virtio::vhost::user::snd::sys::windows::product::SndBackendConfig as SndBackendConfigProduct;
use devices::virtio::BalloonFeatures;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonMode;
use devices::virtio::Console;
#[cfg(feature = "gpu")]
use devices::virtio::GpuParameters;
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::BusDeviceObj;
#[cfg(feature = "gvm")]
use devices::GvmIrqChip;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use devices::IrqChip;
use devices::UserspaceIrqChip;
use devices::VcpuRunState;
use devices::VirtioPciDevice;
#[cfg(feature = "whpx")]
use devices::WhpxSplitIrqChip;
#[cfg(feature = "gpu")]
use gpu_display::EventDevice;
#[cfg(feature = "gvm")]
use hypervisor::gvm::Gvm;
#[cfg(feature = "gvm")]
use hypervisor::gvm::GvmVcpu;
#[cfg(feature = "gvm")]
use hypervisor::gvm::GvmVersion;
#[cfg(feature = "gvm")]
use hypervisor::gvm::GvmVm;
#[cfg(feature = "haxm")]
use hypervisor::haxm::get_use_ghaxm;
#[cfg(feature = "haxm")]
use hypervisor::haxm::set_use_ghaxm;
#[cfg(feature = "haxm")]
use hypervisor::haxm::Haxm;
#[cfg(feature = "haxm")]
use hypervisor::haxm::HaxmVcpu;
#[cfg(feature = "haxm")]
use hypervisor::haxm::HaxmVm;
#[cfg(feature = "whpx")]
use hypervisor::whpx::Whpx;
#[cfg(feature = "whpx")]
use hypervisor::whpx::WhpxFeature;
#[cfg(feature = "whpx")]
use hypervisor::whpx::WhpxVcpu;
#[cfg(feature = "whpx")]
use hypervisor::whpx::WhpxVm;
use hypervisor::Hypervisor;
#[cfg(feature = "whpx")]
use hypervisor::HypervisorCap;
#[cfg(feature = "whpx")]
use hypervisor::HypervisorX86_64;
use hypervisor::ProtectionType;
#[cfg(any(feature = "gvm", feature = "whpx"))]
use hypervisor::Vm;
use irq_wait::IrqWaitWorker;
use jail::FakeMinijailStub as Minijail;
#[cfg(not(feature = "crash-report"))]
pub(crate) use panic_hook::set_panic_hook;
use product::create_snd_mute_tube_pair;
#[cfg(any(feature = "haxm", feature = "gvm", feature = "whpx"))]
use product::create_snd_state_tube;
use product::handle_pvclock_request;
use product::merge_session_invariants;
use product::run_ime_thread;
use product::set_package_name;
pub(crate) use product::setup_metrics_reporting;
use product::start_service_ipc_listener;
use product::RunControlArgs;
use product::ServiceVmState;
use product::Token;
use resources::SystemAllocator;
use run_vcpu::run_all_vcpus;
use run_vcpu::VcpuRunMode;
use rutabaga_gfx::RutabagaGralloc;
use smallvec::SmallVec;
use sync::Mutex;
use tube_transporter::TubeToken;
use tube_transporter::TubeTransporterReader;
use vm_control::api::VmMemoryClient;
use vm_control::BalloonControlCommand;
use vm_control::DeviceControlCommand;
use vm_control::IrqHandlerRequest;
use vm_control::PvClockCommand;
use vm_control::VcpuControl;
use vm_control::VmMemoryRegionState;
use vm_control::VmMemoryRequest;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_control::VmRunMode;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use win_util::ProcessType;
#[cfg(feature = "whpx")]
use x86_64::cpuid::adjust_cpuid;
#[cfg(feature = "whpx")]
use x86_64::cpuid::CpuIdContext;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "haxm"))]
use x86_64::get_cpu_manufacturer;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "haxm"))]
use x86_64::CpuManufacturer;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

use crate::crosvm::config::Config;
use crate::crosvm::config::Executable;
#[cfg(any(feature = "gvm", feature = "whpx"))]
use crate::crosvm::config::IrqChipKind;
#[cfg(feature = "gpu")]
use crate::crosvm::config::TouchDeviceOption;
use crate::crosvm::sys::config::HypervisorKind;
use crate::crosvm::sys::windows::broker::BrokerTubes;
#[cfg(feature = "stats")]
use crate::crosvm::sys::windows::stats::StatisticsCollector;
#[cfg(feature = "gpu")]
pub(crate) use crate::sys::windows::product::get_gpu_product_configs;
#[cfg(feature = "audio")]
pub(crate) use crate::sys::windows::product::get_snd_product_configs;
use crate::sys::windows::product::log_descriptor;
#[cfg(feature = "audio")]
pub(crate) use crate::sys::windows::product::num_input_sound_devices;
#[cfg(feature = "audio")]
pub(crate) use crate::sys::windows::product::num_input_sound_streams;
use crate::sys::windows::product::spawn_anti_tamper_thread;
use crate::sys::windows::product::MetricEventType;

const DEFAULT_GUEST_CID: u64 = 3;

// by default, if enabled, the balloon WS features will use 4 bins.
const VIRTIO_BALLOON_WS_DEFAULT_NUM_BINS: u8 = 4;

enum TaggedControlTube {
    Vm(FlushOnDropTube),
    VmMemory(Tube),
    Product(product::TaggedControlTube),
}

pub enum ExitState {
    Reset,
    Stop,
    Crash,
    #[allow(dead_code)]
    GuestPanic,
    WatchdogReset,
}

type DeviceResult<T = VirtioDeviceStub> = Result<T>;

fn create_vhost_user_block_device(cfg: &Config, disk_device_tube: Tube) -> DeviceResult {
    let features = virtio::base_features(cfg.protection_type);
    let dev =
        virtio::vhost::user::vmm::VhostUserVirtioDevice::new_block(features, disk_device_tube)
            .exit_context(
                Exit::VhostUserBlockDeviceNew,
                "failed to set up vhost-user block device",
            )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

fn create_block_device(cfg: &Config, disk: &DiskOption, disk_device_tube: Tube) -> DeviceResult {
    let features = virtio::base_features(cfg.protection_type);
    let dev = virtio::BlockAsync::new(
        features,
        disk.open()?,
        disk.read_only,
        disk.sparse,
        disk.block_size,
        false,
        disk.id,
        Some(disk_device_tube),
        None,
        None,
        None,
    )
    .exit_context(Exit::BlockDeviceNew, "failed to create block device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_vhost_user_gpu_device(base_features: u64, vhost_user_tube: Tube) -> DeviceResult {
    let dev =
        virtio::vhost::user::vmm::VhostUserVirtioDevice::new_gpu(base_features, vhost_user_tube)
            .exit_context(
                Exit::VhostUserGpuDeviceNew,
                "failed to set up vhost-user gpu device",
            )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_device(
    cfg: &Config,
    gpu_parameters: &GpuParameters,
    vm_evt_wrtube: &SendTube,
    resource_bridges: Vec<Tube>,
    event_devices: Vec<EventDevice>,
    product_args: GpuBackendConfigProduct,
) -> DeviceResult {
    let display_backends = vec![virtio::DisplayBackend::WinApi(
        (&gpu_parameters.display_params[0]).into(),
    )];
    let features = virtio::base_features(cfg.protection_type);
    let dev = product::create_gpu(
        vm_evt_wrtube,
        resource_bridges,
        display_backends,
        gpu_parameters,
        event_devices,
        features,
        product_args,
    )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "audio")]
fn create_snd_device(
    cfg: &Config,
    parameters: SndParameters,
    _product_args: SndBackendConfigProduct,
) -> DeviceResult {
    let features = virtio::base_features(cfg.protection_type);
    let dev = VirtioSnd::new(features, parameters)
        .exit_context(Exit::VirtioSoundDeviceNew, "failed to create snd device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "audio")]
fn create_vhost_user_snd_device(base_features: u64, vhost_user_tube: Tube) -> DeviceResult {
    let dev =
        virtio::vhost::user::vmm::VhostUserVirtioDevice::new_snd(base_features, vhost_user_tube)
            .exit_context(
                Exit::VhostUserSndDeviceNew,
                "failed to set up vhost-user snd device",
            )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_multi_touch_device(
    cfg: &Config,
    multi_touch_spec: &TouchDeviceOption,
    event_pipe: StreamChannel,
    idx: u32,
) -> DeviceResult {
    let (width, height) = multi_touch_spec.get_size();
    let dev = virtio::input::new_multi_touch(
        idx,
        event_pipe,
        width,
        height,
        virtio::base_features(cfg.protection_type),
    )
    .exit_context(Exit::InputDeviceNew, "failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_mouse_device(cfg: &Config, event_pipe: StreamChannel, idx: u32) -> DeviceResult {
    let dev = virtio::input::new_mouse(idx, event_pipe, virtio::base_features(cfg.protection_type))
        .exit_context(Exit::InputDeviceNew, "failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "slirp")]
fn create_vhost_user_net_device(cfg: &Config, net_device_tube: Tube) -> DeviceResult {
    let features = virtio::base_features(cfg.protection_type);
    let dev = virtio::vhost::user::vmm::VhostUserVirtioDevice::new_net(features, net_device_tube)
        .exit_context(
        Exit::VhostUserNetDeviceNew,
        "failed to set up vhost-user net device",
    )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev = virtio::Rng::new(virtio::base_features(cfg.protection_type))
        .exit_context(Exit::RngDeviceNew, "failed to set up rng")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

fn create_console_device(cfg: &Config, param: &SerialParameters) -> DeviceResult {
    let mut keep_rds = Vec::new();
    let evt = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
    let dev = param
        .create_serial_device::<Console>(cfg.protection_type, &evt, &mut keep_rds)
        .exit_context(Exit::CreateConsole, "failed to create console device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "balloon")]
fn create_balloon_device(
    cfg: &Config,
    balloon_device_tube: Tube,
    dynamic_mapping_device_tube: Tube,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
) -> DeviceResult {
    let balloon_features =
        (cfg.balloon_page_reporting as u64) << BalloonFeatures::PageReporting as u64;
    let dev = virtio::Balloon::new(
        virtio::base_features(cfg.protection_type),
        balloon_device_tube,
        VmMemoryClient::new(dynamic_mapping_device_tube),
        inflate_tube,
        init_balloon_size,
        if cfg.strict_balloon {
            BalloonMode::Strict
        } else {
            BalloonMode::Relaxed
        },
        balloon_features,
        #[cfg(feature = "registered_events")]
        None,
        VIRTIO_BALLOON_WS_DEFAULT_NUM_BINS,
    )
    .exit_context(Exit::BalloonDeviceNew, "failed to create balloon")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

fn create_vsock_device(cfg: &Config) -> DeviceResult {
    // We only support a single guest, so we can confidently assign a default
    // CID if one isn't provided. We choose the lowest non-reserved value.
    let dev = virtio::vsock::Vsock::new(
        cfg.vsock
            .as_ref()
            .map(|cfg| cfg.cid)
            .unwrap_or(DEFAULT_GUEST_CID),
        cfg.host_guid.clone(),
        virtio::base_features(cfg.protection_type),
    )
    .exit_context(
        Exit::UserspaceVsockDeviceNew,
        "failed to create userspace vsock device",
    )?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

fn create_virtio_devices(
    cfg: &mut Config,
    vm_evt_wrtube: &SendTube,
    #[allow(clippy::ptr_arg)] control_tubes: &mut Vec<TaggedControlTube>,
    disk_device_tubes: &mut Vec<Tube>,
    balloon_device_tube: Option<Tube>,
    pvclock_device_tube: Option<Tube>,
    dynamic_mapping_device_tube: Option<Tube>,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    tsc_frequency: u64,
    virtio_snd_state_device_tube: Option<Tube>,
    virtio_snd_control_device_tube: Option<Tube>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    if cfg.block_vhost_user_tube.is_empty() {
        // Disk devices must precede virtio-console devices or the kernel does not boot.
        // TODO(b/171215421): figure out why this ordering is required and fix it.
        for disk in &cfg.disks {
            let disk_device_tube = disk_device_tubes.remove(0);
            devs.push(create_block_device(cfg, disk, disk_device_tube)?);
        }
    } else {
        info!("Starting up vhost user block backends...");
        for _disk in &cfg.disks {
            let disk_device_tube = cfg.block_vhost_user_tube.remove(0);
            devs.push(create_vhost_user_block_device(cfg, disk_device_tube)?);
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

    #[cfg(feature = "audio")]
    if product::virtio_sound_enabled() {
        let snd_split_config = cfg
            .snd_split_config
            .as_mut()
            .expect("snd_split_config must exist");
        let snd_vmm_config = snd_split_config
            .vmm_config
            .as_mut()
            .expect("snd_vmm_config must exist");
        product::push_snd_control_tubes(control_tubes, snd_vmm_config);

        match snd_split_config.backend_config.take() {
            None => {
                // No backend config present means the backend is running in another process.
                devs.push(create_vhost_user_snd_device(
                    virtio::base_features(cfg.protection_type),
                    snd_vmm_config
                        .main_vhost_user_tube
                        .take()
                        .expect("Snd VMM vhost-user tube should be set"),
                )?);
            }
            Some(backend_config) => {
                // Backend config present, so initialize Snd in this process.
                devs.push(create_snd_device(
                    cfg,
                    backend_config.parameters,
                    backend_config.product_config,
                )?);
            }
        }
    }

    if let Some(tube) = pvclock_device_tube {
        product::push_pvclock_device(cfg, &mut devs, tsc_frequency, tube);
    }

    devs.push(create_rng_device(cfg)?);

    #[cfg(feature = "slirp")]
    if let Some(net_vhost_user_tube) = cfg.net_vhost_user_tube.take() {
        devs.push(create_vhost_user_net_device(cfg, net_vhost_user_tube)?);
    }

    if let (Some(balloon_device_tube), Some(dynamic_mapping_device_tube)) =
        (balloon_device_tube, dynamic_mapping_device_tube)
    {
        devs.push(create_balloon_device(
            cfg,
            balloon_device_tube,
            dynamic_mapping_device_tube,
            inflate_tube,
            init_balloon_size,
        )?);
    }

    devs.push(create_vsock_device(cfg)?);

    #[cfg(feature = "gpu")]
    if let Some(gpu_vmm_config) = cfg.gpu_vmm_config.take() {
        devs.extend(create_virtio_gpu_and_input_devices(
            cfg,
            gpu_vmm_config,
            control_tubes,
        )?);
    }

    Ok(devs)
}

#[cfg(feature = "gpu")]
fn create_virtio_gpu_and_input_devices(
    cfg: &mut Config,
    mut gpu_vmm_config: GpuVmmConfig,
    #[allow(clippy::ptr_arg)] control_tubes: &mut Vec<TaggedControlTube>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();
    let resource_bridges = Vec::<Tube>::new();

    if !cfg.virtio_single_touch.is_empty() {
        unimplemented!("--single-touch is no longer supported. Use --multi-touch instead.");
    }

    product::push_gpu_control_tubes(control_tubes, &mut gpu_vmm_config);

    // Iterate event devices, create the VMM end.
    for (idx, pipe) in gpu_vmm_config
        .input_event_multi_touch_pipes
        .drain(..)
        .enumerate()
    {
        devs.push(create_multi_touch_device(
            cfg,
            &cfg.virtio_multi_touch[idx],
            pipe,
            idx as u32,
        )?);
    }

    product::push_mouse_device(cfg, &mut gpu_vmm_config, &mut devs)?;

    for (idx, pipe) in gpu_vmm_config.input_event_mouse_pipes.drain(..).enumerate() {
        devs.push(create_mouse_device(cfg, pipe, idx as u32)?);
    }

    let keyboard_pipe = gpu_vmm_config
        .input_event_keyboard_pipes
        .pop()
        .expect("at least one keyboard should be in GPU VMM config");
    let dev = virtio::input::new_keyboard(
        /* idx= */ 0,
        keyboard_pipe,
        virtio::base_features(cfg.protection_type),
    )
    .exit_context(Exit::InputDeviceNew, "failed to set up input device")?;

    devs.push(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    });

    match cfg.gpu_backend_config.take() {
        None => {
            // No backend config present means the backend is running in another process.
            devs.push(create_vhost_user_gpu_device(
                virtio::base_features(cfg.protection_type),
                gpu_vmm_config
                    .main_vhost_user_tube
                    .take()
                    .expect("GPU VMM vhost-user tube should be set"),
            )?);
        }
        Some(backend_config) => {
            // Backend config present, so initialize GPU in this process.
            devs.push(create_gpu_device(
                cfg,
                &backend_config.params,
                &backend_config.exit_evt_wrtube,
                resource_bridges,
                backend_config.event_devices,
                backend_config.product_config,
            )?);
        }
    }

    Ok(devs)
}

fn create_devices(
    cfg: &mut Config,
    mem: &GuestMemory,
    exit_evt_wrtube: &SendTube,
    irq_control_tubes: &mut Vec<Tube>,
    control_tubes: &mut Vec<TaggedControlTube>,
    disk_device_tubes: &mut Vec<Tube>,
    balloon_device_tube: Option<Tube>,
    pvclock_device_tube: Option<Tube>,
    dynamic_mapping_device_tube: Option<Tube>,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    #[allow(unused)] ac97_device_tubes: Vec<Tube>,
    tsc_frequency: u64,
    virtio_snd_state_device_tube: Option<Tube>,
    virtio_snd_control_device_tube: Option<Tube>,
) -> DeviceResult<Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>> {
    let stubs = create_virtio_devices(
        cfg,
        exit_evt_wrtube,
        control_tubes,
        disk_device_tubes,
        balloon_device_tube,
        pvclock_device_tube,
        dynamic_mapping_device_tube,
        inflate_tube,
        init_balloon_size,
        tsc_frequency,
        virtio_snd_state_device_tube,
        virtio_snd_control_device_tube,
    )?;

    let mut pci_devices = Vec::new();

    for stub in stubs {
        let (msi_host_tube, msi_device_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        irq_control_tubes.push(msi_host_tube);

        let shared_memory_tube = if stub.dev.get_shared_memory_region().is_some() {
            let (host_tube, device_tube) =
                Tube::pair().context("failed to create VVU proxy tube")?;
            control_tubes.push(TaggedControlTube::VmMemory(host_tube));
            Some(device_tube)
        } else {
            None
        };

        let (ioevent_host_tube, ioevent_device_tube) =
            Tube::pair().context("failed to create ioevent tube")?;
        control_tubes.push(TaggedControlTube::VmMemory(ioevent_host_tube));

        let dev = Box::new(
            VirtioPciDevice::new(
                mem.clone(),
                stub.dev,
                msi_device_tube,
                cfg.disable_virtio_intx,
                shared_memory_tube.map(VmMemoryClient::new),
                VmMemoryClient::new(ioevent_device_tube),
            )
            .exit_context(Exit::VirtioPciDev, "failed to create virtio pci dev")?,
        ) as Box<dyn BusDeviceObj>;
        pci_devices.push((dev, stub.jail));
    }

    #[cfg(feature = "audio")]
    if !product::virtio_sound_enabled() {
        if cfg.ac97_parameters.len() != ac97_device_tubes.len() {
            panic!(
                "{} Ac97 device(s) will be made, but only {} Ac97 device tubes are present.",
                cfg.ac97_parameters.len(),
                ac97_device_tubes.len()
            );
        }

        for (ac97_param, ac97_device_tube) in cfg
            .ac97_parameters
            .iter()
            .zip(ac97_device_tubes.into_iter())
        {
            let dev = Ac97Dev::try_new(mem.clone(), ac97_param.clone(), ac97_device_tube)
                .exit_context(Exit::CreateAc97, "failed to create ac97 device")?;
            pci_devices.push((Box::new(dev), None));
        }
    }

    Ok(pci_devices)
}

#[derive(Debug)]
struct PvClockError(String);

fn handle_readable_event<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    event: &TriggeredEvent<Token>,
    vm_control_indices_to_remove: &mut Vec<usize>,
    service_vm_state: &mut ServiceVmState,
    ac97_host_tubes: &[Tube],
    disk_host_tubes: &[Tube],
    ipc_main_loop_tube: Option<&Tube>,
    vm_evt_rdtube: &RecvTube,
    control_tubes: &mut Vec<TaggedControlTube>,
    guest_os: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator_mutex: &Arc<Mutex<SystemAllocator>>,
    gralloc: &mut RutabagaGralloc,
    virtio_snd_host_mute_tube: &mut Option<Tube>,
    proto_main_loop_tube: Option<&ProtoTube>,
    anti_tamper_main_thread_tube: &Option<ProtoTube>,
    balloon_host_tube: &Option<Tube>,
    memory_size_mb: u64,
    vcpu_boxes: &Mutex<Vec<Box<dyn VcpuArch>>>,
    pvclock_host_tube: &Option<Tube>,
    run_mode_arc: &VcpuRunMode,
    region_state: &mut VmMemoryRegionState,
    vm_control_server: Option<&mut ControlServer>,
    irq_handler_control: &Tube,
    device_ctrl_tube: &Tube,
    wait_ctx: &WaitContext<Token>,
    force_s2idle: bool,
    vcpu_control_channels: &[mpsc::Sender<VcpuControl>],
) -> Result<(bool, Option<ExitState>)> {
    match event.token {
        Token::VmEvent => match vm_evt_rdtube.recv::<VmEventType>() {
            Ok(vm_event) => {
                let exit_state = match vm_event {
                    VmEventType::Exit => {
                        info!("vcpu requested shutdown");
                        Some(ExitState::Stop)
                    }
                    VmEventType::Reset => {
                        info!("vcpu requested reset");
                        Some(ExitState::Reset)
                    }
                    VmEventType::Crash => {
                        info!("vcpu crashed");
                        Some(ExitState::Crash)
                    }
                    VmEventType::Panic(_) => {
                        error!("got pvpanic event. this event is not expected on Windows.");
                        None
                    }
                    VmEventType::WatchdogReset => {
                        info!("vcpu stall detected");
                        Some(ExitState::WatchdogReset)
                    }
                };
                return Ok((exit_state.is_some(), exit_state));
            }
            Err(e) => {
                warn!("failed to recv VmEvent: {}", e);
            }
        },
        Token::BrokerShutdown => {
            info!("main loop got broker shutdown event");
            return Ok((true, None));
        }
        Token::VmControlServer => {
            let server =
                vm_control_server.expect("control server must exist if this event triggers");
            let client = server.accept();
            wait_ctx
                .add(
                    client.0.get_read_notifier(),
                    Token::VmControl {
                        index: control_tubes.len(),
                    },
                )
                .exit_context(
                    Exit::WaitContextAdd,
                    "failed to add trigger to wait context",
                )?;
            wait_ctx
                .add(
                    client.0.get_close_notifier(),
                    Token::VmControl {
                        index: control_tubes.len(),
                    },
                )
                .exit_context(
                    Exit::WaitContextAdd,
                    "failed to add trigger to wait context",
                )?;
            control_tubes.push(TaggedControlTube::Vm(client));
        }
        #[allow(clippy::collapsible_match)]
        Token::VmControl { index } => {
            if let Some(tube) = control_tubes.get(index) {
                #[allow(clippy::single_match)]
                match tube {
                    TaggedControlTube::VmMemory(tube) => match tube.recv::<VmMemoryRequest>() {
                        Ok(request) => {
                            let response = request.execute(
                                &mut guest_os.vm,
                                &mut sys_allocator_mutex.lock(),
                                gralloc,
                                None,
                                region_state,
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
                    TaggedControlTube::Product(product_tube) => {
                        product::handle_tagged_control_tube_event(
                            product_tube,
                            virtio_snd_host_mute_tube,
                            service_vm_state,
                            ipc_main_loop_tube,
                            ac97_host_tubes,
                        )
                    }
                    TaggedControlTube::Vm(tube) => match tube.0.recv::<VmRequest>() {
                        Ok(request) => {
                            let mut run_mode_opt = None;
                            let response = match request {
                                VmRequest::HotPlugCommand { device, add } => {
                                    // Suppress warnings.
                                    let _ = (device, add);
                                    unimplemented!("not implemented on Windows");
                                }
                                #[cfg(feature = "registered_events")]
                                VmRequest::RegisterListener { socket_addr, event } => {
                                    unimplemented!("not implemented on Windows");
                                }
                                #[cfg(feature = "registered_events")]
                                VmRequest::UnregisterListener { socket_addr, event } => {
                                    unimplemented!("not implemented on Windows");
                                }
                                #[cfg(feature = "registered_events")]
                                VmRequest::Unregister { socket_addr } => {
                                    unimplemented!("not implemented on Windows");
                                }
                                _ => {
                                    #[cfg(feature = "balloon")]
                                    let mut balloon_stats_id = 0;
                                    #[cfg(feature = "balloon")]
                                    let mut balloon_wss_id = 0;
                                    let vcpu_size = vcpu_boxes.lock().len();
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        #[cfg(feature = "balloon")]
                                        balloon_host_tube.as_ref(),
                                        #[cfg(feature = "balloon")]
                                        &mut balloon_stats_id,
                                        #[cfg(feature = "balloon")]
                                        &mut balloon_wss_id,
                                        disk_host_tubes,
                                        &mut guest_os.pm,
                                        #[cfg(feature = "gpu")]
                                        None,
                                        None,
                                        &mut None,
                                        |msg| {
                                            kick_all_vcpus(
                                                run_mode_arc,
                                                vcpu_control_channels,
                                                vcpu_boxes,
                                                guest_os.irq_chip.as_ref(),
                                                pvclock_host_tube,
                                                msg,
                                            );
                                        },
                                        |msg, index| {
                                            kick_vcpu(
                                                run_mode_arc,
                                                vcpu_control_channels,
                                                vcpu_boxes,
                                                guest_os.irq_chip.as_ref(),
                                                pvclock_host_tube,
                                                index,
                                                msg,
                                            );
                                        },
                                        force_s2idle,
                                        #[cfg(feature = "swap")]
                                        None,
                                        device_ctrl_tube,
                                        vcpu_size,
                                        irq_handler_control,
                                        || guest_os.irq_chip.as_ref().snapshot(vcpu_size),
                                        |snapshot| {
                                            guest_os
                                                .irq_chip
                                                .try_box_clone()?
                                                .restore(snapshot, vcpu_size)
                                        },
                                    );

                                    response
                                }
                            };

                            if let Err(e) = tube.0.send(&response) {
                                error!("failed to send VmResponse: {}", e);
                            }

                            if let Some(run_mode) = run_mode_opt {
                                info!("control socket changed run mode to {}", run_mode);
                                match run_mode {
                                    VmRunMode::Exiting => {
                                        unimplemented!("not implemented on Windows");
                                    }
                                    other => {
                                        if other == VmRunMode::Running {
                                            for dev in &guest_os.resume_notify_devices {
                                                dev.lock().resume_imminent();
                                            }
                                        }
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
                }
            }
        }
        #[allow(unreachable_patterns)]
        _ => product::handle_received_token(
            &event.token,
            ac97_host_tubes,
            anti_tamper_main_thread_tube,
            balloon_host_tube,
            control_tubes,
            guest_os,
            ipc_main_loop_tube,
            memory_size_mb,
            proto_main_loop_tube,
            pvclock_host_tube,
            run_mode_arc,
            service_vm_state,
            vcpu_boxes,
            virtio_snd_host_mute_tube,
        ),
    };
    Ok((false, None))
}

fn create_control_server(
    control_server_path: Option<PathBuf>,
    wait_ctx: &WaitContext<Token>,
) -> Result<Option<ControlServer>> {
    #[cfg(not(feature = "prod-build"))]
    {
        if let Some(path) = control_server_path {
            let server =
                ControlServer::new(path.to_str().expect("control socket path must be a string"))
                    .exit_context(
                        Exit::FailedToCreateControlServer,
                        "failed to create control server",
                    )?;
            wait_ctx
                .add(server.client_waiting(), Token::VmControlServer)
                .exit_context(
                    Exit::WaitContextAdd,
                    "failed to add control server to wait context",
                )?;
            return Ok(Some(server));
        }
    }
    Ok::<Option<ControlServer>, anyhow::Error>(None)
}

fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    mut guest_os: RunnableLinuxVm<V, Vcpu>,
    sys_allocator: SystemAllocator,
    mut control_tubes: Vec<TaggedControlTube>,
    irq_control_tubes: Vec<Tube>,
    vm_evt_rdtube: RecvTube,
    vm_evt_wrtube: SendTube,
    broker_shutdown_evt: Option<Event>,
    balloon_host_tube: Option<Tube>,
    pvclock_host_tube: Option<Tube>,
    disk_host_tubes: Vec<Tube>,
    mut gralloc: RutabagaGralloc,
    #[cfg(feature = "stats")] stats: Option<Arc<Mutex<StatisticsCollector>>>,
    service_pipe_name: Option<String>,
    ac97_host_tubes: Vec<Tube>,
    memory_size_mb: u64,
    host_cpu_topology: bool,
    tsc_sync_mitigations: TscSyncMitigations,
    force_calibrated_tsc_leaf: bool,
    mut product_args: RunControlArgs,
    mut virtio_snd_host_mute_tube: Option<Tube>,
    restore_path: Option<PathBuf>,
    control_server_path: Option<PathBuf>,
    force_s2idle: bool,
    suspended: bool,
) -> Result<ExitState> {
    let (ipc_main_loop_tube, proto_main_loop_tube, _service_ipc) =
        start_service_ipc_listener(service_pipe_name)?;

    let mut service_vm_state = product::create_service_vm_state(memory_size_mb);

    let sys_allocator_mutex = Arc::new(Mutex::new(sys_allocator));

    let exit_evt = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
    let (irq_handler_control, irq_handler_control_for_worker) = Tube::pair().exit_context(
        Exit::CreateTube,
        "failed to create IRQ handler control Tube",
    )?;

    // Create a separate thread to wait on IRQ events. This is a natural division
    // because IRQ interrupts have no dependencies on other events, and this lets
    // us avoid approaching the Windows WaitForMultipleObjects 64-object limit.
    let irq_join_handle = IrqWaitWorker::start(
        irq_handler_control_for_worker,
        guest_os
            .irq_chip
            .try_box_clone()
            .exit_context(Exit::CloneEvent, "failed to clone irq chip")?,
        irq_control_tubes,
        sys_allocator_mutex.clone(),
    );

    let mut triggers = vec![(vm_evt_rdtube.get_read_notifier(), Token::VmEvent)];
    product::push_triggers(&mut triggers, &ipc_main_loop_tube, &proto_main_loop_tube);
    let wait_ctx = WaitContext::build_with(&triggers).exit_context(
        Exit::WaitContextAdd,
        "failed to add trigger to wait context",
    )?;

    if let Some(evt) = broker_shutdown_evt.as_ref() {
        wait_ctx.add(evt, Token::BrokerShutdown).exit_context(
            Exit::WaitContextAdd,
            "failed to add trigger to wait context",
        )?;
    }

    for (index, control_tube) in control_tubes.iter().enumerate() {
        #[allow(clippy::single_match)]
        match control_tube {
            TaggedControlTube::VmMemory(tube) => {
                wait_ctx
                    .add(tube.get_read_notifier(), Token::VmControl { index })
                    .exit_context(
                        Exit::WaitContextAdd,
                        "failed to add trigger to wait context",
                    )?;
            }
            TaggedControlTube::Product(product_tube) => wait_ctx
                .add(product_tube.get_read_notifier(), Token::VmControl { index })
                .exit_context(
                    Exit::WaitContextAdd,
                    "failed to add trigger to wait context",
                )?,
            _ => (),
        }
    }

    let (device_ctrl_tube, device_ctrl_resp) = Tube::pair().context("failed to create tube")?;
    guest_os.devices_thread = match create_devices_worker_thread(
        guest_os.vm.get_memory().clone(),
        guest_os.io_bus.clone(),
        guest_os.mmio_bus.clone(),
        device_ctrl_resp,
    ) {
        Ok(join_handle) => Some(join_handle),
        Err(e) => {
            return Err(anyhow!("Failed to start devices thread: {}", e));
        }
    };

    let vcpus: Vec<Option<_>> = match guest_os.vcpus.take() {
        Some(vec) => vec.into_iter().map(|vcpu| Some(vcpu)).collect(),
        None => iter::repeat_with(|| None)
            .take(guest_os.vcpu_count)
            .collect(),
    };

    let anti_tamper_main_thread_tube = spawn_anti_tamper_thread(&wait_ctx);

    let mut vm_control_server = create_control_server(control_server_path, &wait_ctx)?;

    let ime_thread = run_ime_thread(&mut product_args, &exit_evt)?;

    let original_terminal_mode = stdin().set_raw_mode().ok();

    let vcpu_boxes: Arc<Mutex<Vec<Box<dyn VcpuArch>>>> = Arc::new(Mutex::new(Vec::new()));
    let run_mode_arc = Arc::new(VcpuRunMode::default());

    let run_mode_state = if suspended {
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
        run_mode_arc.set_and_notify(VmRunMode::Suspending);
        VmRunMode::Suspending
    } else {
        VmRunMode::Running
    };

    // If we are restoring from a snapshot, then start suspended.
    if restore_path.is_some() {
        run_mode_arc.set_and_notify(VmRunMode::Suspending);
    }

    let (vcpu_threads, vcpu_control_channels) = run_all_vcpus(
        vcpus,
        vcpu_boxes.clone(),
        &guest_os,
        &exit_evt,
        &vm_evt_wrtube,
        #[cfg(feature = "stats")]
        &stats,
        host_cpu_topology,
        run_mode_arc.clone(),
        tsc_sync_mitigations,
        force_calibrated_tsc_leaf,
    )?;

    // Restore VM (if applicable).
    if let Some(path) = restore_path {
        vm_control::do_restore(
            path,
            |msg| {
                kick_all_vcpus(
                    run_mode_arc.as_ref(),
                    &vcpu_control_channels,
                    vcpu_boxes.as_ref(),
                    guest_os.irq_chip.as_ref(),
                    &pvclock_host_tube,
                    msg,
                )
            },
            |msg, index| {
                kick_vcpu(
                    run_mode_arc.as_ref(),
                    &vcpu_control_channels,
                    vcpu_boxes.as_ref(),
                    guest_os.irq_chip.as_ref(),
                    &pvclock_host_tube,
                    index,
                    msg,
                )
            },
            &irq_handler_control,
            &device_ctrl_tube,
            guest_os.vcpu_count,
            |image| {
                guest_os
                    .irq_chip
                    .try_box_clone()?
                    .restore(image, guest_os.vcpu_count)
            },
        )?;
        // Allow the vCPUs to start for real.
        kick_all_vcpus(
            run_mode_arc.as_ref(),
            &vcpu_control_channels,
            vcpu_boxes.as_ref(),
            guest_os.irq_chip.as_ref(),
            &pvclock_host_tube,
            // Other platforms (unix) have multiple modes they could start in (e.g. starting for
            // guest kernel debugging, etc). If/when we support those modes on Windows, we'll need
            // to enter that mode here rather than VmRunMode::Running.
            VcpuControl::RunState(run_mode_state),
        );
    }

    let mut exit_state = ExitState::Stop;
    let mut region_state = VmMemoryRegionState::new();

    'poll: loop {
        let events = {
            match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to wait: {}", e);
                    break;
                }
            }
        };

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            let (break_poll, state) = handle_readable_event(
                event,
                &mut vm_control_indices_to_remove,
                &mut service_vm_state,
                disk_host_tubes.as_slice(),
                &ac97_host_tubes,
                ipc_main_loop_tube.as_ref(),
                &vm_evt_rdtube,
                &mut control_tubes,
                &mut guest_os,
                &sys_allocator_mutex,
                &mut gralloc,
                &mut virtio_snd_host_mute_tube,
                proto_main_loop_tube.as_ref(),
                &anti_tamper_main_thread_tube,
                &balloon_host_tube,
                memory_size_mb,
                vcpu_boxes.as_ref(),
                &pvclock_host_tube,
                run_mode_arc.as_ref(),
                &mut region_state,
                vm_control_server.as_mut(),
                &irq_handler_control,
                &device_ctrl_tube,
                &wait_ctx,
                force_s2idle,
                &vcpu_control_channels,
            )?;
            if let Some(state) = state {
                exit_state = state;
            }
            if break_poll {
                break 'poll;
            }
        }

        remove_closed_tubes(&wait_ctx, &mut control_tubes, vm_control_indices_to_remove)?;
    }

    info!("run_control poll loop completed, forcing vCPUs to exit...");

    // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
    run_mode_arc.set_and_notify(VmRunMode::Exiting);

    // Force all vcpus to exit from the hypervisor
    for vcpu in vcpu_boxes.lock().iter() {
        vcpu.set_immediate_exit(true);
    }

    let mut res = Ok(exit_state);
    guest_os.irq_chip.kick_halted_vcpus();
    let _ = exit_evt.signal();

    // Shut down the IRQ handler thread.
    if let Err(e) = irq_handler_control.send(&IrqHandlerRequest::Exit) {
        error!("failed to request exit from IRQ handler thread: {}", e);
    }

    // Ensure any child threads have ended by sending the Exit vm event (possibly again) to ensure
    // their run loops are aborted.
    let _ = vm_evt_wrtube.send::<VmEventType>(&VmEventType::Exit);
    for (i, thread) in vcpu_threads.into_iter().enumerate() {
        // wait till all the threads exit, so that guest_os.vm arc memory count is down to 1.
        // otherwise, we will hit a memory leak if we force kill the thread with terminate.
        match thread.join() {
            Ok(Err(e)) => {
                error!("vcpu thread {} exited with an error: {}", i, e);
                res = Err(e);
            }
            Ok(_) => {}
            Err(e) => error!("vcpu thread {} panicked: {:?}", i, e),
        }
    }

    info!("vCPU threads have exited.");

    if let Some(ime) = ime_thread {
        match ime.join() {
            Ok(Err(e)) => {
                error!("ime thread exited with an error: {}", e);
                if res.is_ok() {
                    // Prioritize past errors, but return this error if it is unique, otherwise just
                    // log it.
                    res = Err(e)
                }
            }
            Ok(_) => {}
            Err(e) => error!("ime thread panicked: {:?}", e),
        }
    }
    info!("IME thread has exited.");

    // This cancels all the outstanding and any future blocking operations.
    // TODO(b/196911556): Shutdown executor for cleaner shutdown. Given we are using global, for a
    // cleaner shutdown we have to call disarm so that all the incoming requests are run and are
    // cancelled. If we call shutdown all blocking threads will go away and incoming operations
    // won't be scheduled to run and will be dropped leading to panic. I think ideal place to call
    // shutdown is when we drop non-global executor.
    cros_async::unblock_disarm();
    info!("blocking async pool has shut down.");

    let _ = irq_join_handle.join();
    info!("IrqWaitWorker has shut down.");

    #[cfg(feature = "stats")]
    if let Some(stats) = stats {
        println!("Statistics Collected:\n{}", stats.lock());
        println!("Statistics JSON:\n{}", stats.lock().json());
    }

    if let Some(mode) = original_terminal_mode {
        if let Err(e) = stdin().restore_mode(mode) {
            warn!("failed to restore terminal mode: {}", e);
        }
    }

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control tubes are closed when this function exits.
    mem::drop(guest_os);

    info!("guest_os dropped, run_control is done.");

    res
}

/// Remove Tubes that have been closed from the WaitContext.
fn remove_closed_tubes(
    wait_ctx: &WaitContext<Token>,
    tubes: &mut Vec<TaggedControlTube>,
    mut tube_indices_to_remove: Vec<usize>,
) -> anyhow::Result<()> {
    // Sort in reverse so the highest indexes are removed first. This removal algorithm
    // preserves correct indexes as each element is removed. (Consider the input [0, 10], with 10
    // being the last item in the `tubes` list. If we remove 0 first, 10 is swapped to 0, and then
    // index 10 is dropped. Then we would attempt to remove item 10 and go out of range. If we
    // remove the largest first, this problem does not occur.)
    tube_indices_to_remove.sort_unstable_by_key(|&k| Reverse(k));
    tube_indices_to_remove.dedup();
    for index in tube_indices_to_remove {
        if let Some(socket) = tubes.get(index) {
            match socket {
                TaggedControlTube::VmMemory(t) => {
                    wait_ctx
                        .delete(t.get_read_notifier())
                        .context("failed to remove descriptor from wait context")?;
                }
                TaggedControlTube::Product(t) => {
                    wait_ctx
                        .delete(t.get_read_notifier())
                        .context("failed to remove descriptor from wait context")?;
                }
                TaggedControlTube::Vm(t) => {
                    wait_ctx
                        .delete(t.0.get_close_notifier())
                        .context("failed to remove descriptor from wait context")?;
                    wait_ctx
                        .delete(t.0.get_read_notifier())
                        .context("failed to remove descriptor from wait context")?;
                }
            }
        }

        // This line implicitly drops the socket at `index` when it gets returned by
        // `swap_remove`. After this line, the socket at `index` is not the one from
        // `tube_indices_to_remove`. Because of this socket's change in index, we need to
        // use `wait_ctx.modify` to change the associated index in its `Token::VmControl`.
        tubes.swap_remove(index);
        if let Some(tube) = tubes.get(index) {
            match tube {
                TaggedControlTube::VmMemory(t) => {
                    wait_ctx
                        .modify(
                            t.get_read_notifier(),
                            EventType::Read,
                            Token::VmControl { index },
                        )
                        .context("failed to remove descriptor from wait context")?;
                }
                TaggedControlTube::Product(t) => {
                    wait_ctx
                        .modify(
                            t.get_read_notifier(),
                            EventType::Read,
                            Token::VmControl { index },
                        )
                        .context("failed to remove descriptor from wait context")?;
                }
                TaggedControlTube::Vm(t) => {
                    wait_ctx
                        .modify(
                            t.0.get_read_notifier(),
                            EventType::Read,
                            Token::VmControl { index },
                        )
                        .context("failed to remove descriptor from wait context")?;
                    wait_ctx
                        .modify(
                            t.0.get_close_notifier(),
                            EventType::Read,
                            Token::VmControl { index },
                        )
                        .context("failed to remove descriptor from wait context")?;
                }
            }
        }
    }
    Ok(())
}

/// Sends a message to all VCPUs.
fn kick_all_vcpus(
    run_mode: &VcpuRunMode,
    vcpu_control_channels: &[mpsc::Sender<VcpuControl>],
    vcpu_boxes: &Mutex<Vec<Box<dyn VcpuArch>>>,
    irq_chip: &dyn IrqChipArch,
    pvclock_host_tube: &Option<Tube>,
    msg: VcpuControl,
) {
    // On Windows, we handle run mode switching directly rather than delegating to the VCPU thread
    // like unix does.
    match &msg {
        VcpuControl::RunState(VmRunMode::Suspending) => {
            suspend_all_vcpus(run_mode, vcpu_boxes, irq_chip, pvclock_host_tube);
            return;
        }
        VcpuControl::RunState(VmRunMode::Running) => {
            resume_all_vcpus(run_mode, vcpu_boxes, irq_chip, pvclock_host_tube);
            return;
        }
        _ => (),
    }

    // For non RunState commands, we dispatch just like unix would.
    for vcpu in vcpu_control_channels {
        if let Err(e) = vcpu.send(msg.clone()) {
            error!("failed to send VcpuControl message: {}", e);
        }
    }

    // Now that we've sent a message, we need VCPUs to exit so they can process it.
    for vcpu in vcpu_boxes.lock().iter() {
        vcpu.set_immediate_exit(true);
    }
    irq_chip.kick_halted_vcpus();

    // If the VCPU isn't running, we have to notify the run_mode condvar to wake it so it processes
    // the control message.
    let current_run_mode = run_mode.get_mode();
    if current_run_mode != VmRunMode::Running {
        run_mode.set_and_notify(current_run_mode);
    }
}

/// Sends a message to a single VCPU. On Windows, `VcpuControl::RunState` cannot be sent to a single
/// VCPU.
fn kick_vcpu(
    run_mode: &VcpuRunMode,
    vcpu_control_channels: &[mpsc::Sender<VcpuControl>],
    vcpu_boxes: &Mutex<Vec<Box<dyn VcpuArch>>>,
    irq_chip: &dyn IrqChipArch,
    pvclock_host_tube: &Option<Tube>,
    index: usize,
    msg: VcpuControl,
) {
    assert!(
        !matches!(msg, VcpuControl::RunState(_)),
        "Windows does not support RunState changes on a per VCPU basis"
    );

    let vcpu = vcpu_control_channels
        .get(index)
        .expect("invalid vcpu index specified");
    if let Err(e) = vcpu.send(msg) {
        error!("failed to send VcpuControl message: {}", e);
    }

    // Now that we've sent a message, we need the VCPU to exit so it can
    // process the message.
    vcpu_boxes
        .lock()
        .get(index)
        .expect("invalid vcpu index specified")
        .set_immediate_exit(true);
    irq_chip.kick_halted_vcpus();

    // If the VCPU isn't running, we have to notify the run_mode condvar to wake it so it processes
    // the control message. (Technically this wakes all VCPUs, but those without messages will go
    // back to sleep.)
    let current_run_mode = run_mode.get_mode();
    if current_run_mode != VmRunMode::Running {
        run_mode.set_and_notify(current_run_mode);
    }
}

/// Suspends all VCPUs. The VM will be effectively frozen in time once this function is called,
/// though devices on the host will continue to run.
pub(crate) fn suspend_all_vcpus(
    run_mode: &VcpuRunMode,
    vcpu_boxes: &Mutex<Vec<Box<dyn VcpuArch>>>,
    irq_chip: &dyn IrqChipArch,
    pvclock_host_tube: &Option<Tube>,
) {
    // VCPU threads MUST see the VmRunMode::Suspending flag first, otherwise
    // they may re-enter the VM.
    run_mode.set_and_notify(VmRunMode::Suspending);

    // Force all vcpus to exit from the hypervisor
    for vcpu in vcpu_boxes.lock().iter() {
        vcpu.set_immediate_exit(true);
    }
    irq_chip.kick_halted_vcpus();

    handle_pvclock_request(pvclock_host_tube, PvClockCommand::Suspend)
        .unwrap_or_else(|e| error!("Error handling pvclock suspend: {:?}", e));
}

/// Resumes all VCPUs.
pub(crate) fn resume_all_vcpus(
    run_mode: &VcpuRunMode,
    vcpu_boxes: &Mutex<Vec<Box<dyn VcpuArch>>>,
    irq_chip: &dyn IrqChipArch,
    pvclock_host_tube: &Option<Tube>,
) {
    handle_pvclock_request(pvclock_host_tube, PvClockCommand::Resume)
        .unwrap_or_else(|e| error!("Error handling pvclock resume: {:?}", e));

    // Make sure any immediate exit bits are disabled
    for vcpu in vcpu_boxes.lock().iter() {
        vcpu.set_immediate_exit(false);
    }

    run_mode.set_and_notify(VmRunMode::Running);
}

#[cfg(feature = "gvm")]
const GVM_MINIMUM_VERSION: GvmVersion = GvmVersion {
    major: 1,
    minor: 4,
    patch: 1,
};

#[cfg(feature = "gvm")]
fn create_gvm_vm(gvm: Gvm, mem: GuestMemory) -> Result<GvmVm> {
    match gvm.get_full_version() {
        Ok(version) => {
            if version < GVM_MINIMUM_VERSION {
                error!(
                    "GVM version {} is below minimum version {}",
                    version, GVM_MINIMUM_VERSION
                );
                return Err(base::Error::new(libc::ENXIO).into());
            } else {
                info!("Using GVM version {}.", version)
            }
        }
        Err(e) => {
            error!("unable to determine gvm version: {}", e);
            return Err(base::Error::new(libc::ENXIO).into());
        }
    }
    let vm = GvmVm::new(&gvm, mem)?;
    Ok(vm)
}

#[cfg(feature = "haxm")]
fn create_haxm_vm(
    haxm: Haxm,
    mem: GuestMemory,
    kernel_log_file: &Option<String>,
) -> Result<HaxmVm> {
    let vm = HaxmVm::new(&haxm, mem)?;
    if let Some(path) = kernel_log_file {
        use hypervisor::haxm::HAX_CAP_VM_LOG;
        if vm.check_raw_capability(HAX_CAP_VM_LOG) {
            match vm.register_log_file(path) {
                Ok(_) => {}
                Err(e) => match e.errno() {
                    libc::E2BIG => {
                        error!(
                            "kernel_log_file path is too long, kernel log file will not be written"
                        );
                    }
                    _ => return Err(e.into()),
                },
            }
        } else {
            warn!(
                "kernel_log_file specified but this version of HAXM does not support kernel log \
                  files"
            );
        }
    }
    Ok(vm)
}

#[cfg(feature = "whpx")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn create_whpx_vm(
    whpx: Whpx,
    mem: GuestMemory,
    cpu_count: usize,
    no_smt: bool,
    apic_emulation: bool,
    force_calibrated_tsc_leaf: bool,
    vm_evt_wrtube: SendTube,
) -> Result<WhpxVm> {
    let cpu_config = hypervisor::CpuConfigX86_64::new(
        force_calibrated_tsc_leaf,
        false, /* host_cpu_topology */
        false, /* enable_hwp */
        false, /* enable_pnp_data */
        no_smt,
        false, /* itmt */
        None,  /* hybrid_type */
    );

    // context for non-cpu-specific cpuid results
    let ctx = CpuIdContext::new(
        0,
        cpu_count,
        None,
        cpu_config,
        whpx.check_capability(HypervisorCap::CalibratedTscLeafRequired),
        __cpuid_count,
        __cpuid,
    );

    // Get all cpuid entries that we should pre-set
    let mut cpuid = whpx.get_supported_cpuid()?;

    // Adjust them for crosvm
    for entry in cpuid.cpu_id_entries.iter_mut() {
        adjust_cpuid(entry, &ctx);
    }

    let vm = WhpxVm::new(
        &whpx,
        cpu_count,
        mem,
        cpuid,
        apic_emulation,
        Some(vm_evt_wrtube),
    )
    .exit_context(Exit::WhpxSetupError, "failed to create WHPX vm")?;

    Ok(vm)
}

#[cfg(feature = "gvm")]
fn create_gvm_irq_chip(vm: &GvmVm, vcpu_count: usize) -> base::Result<GvmIrqChip> {
    info!("Creating GVM irqchip");
    let irq_chip = GvmIrqChip::new(vm.try_clone()?, vcpu_count)?;
    Ok(irq_chip)
}

#[cfg(feature = "whpx")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn create_whpx_split_irq_chip(
    vm: &WhpxVm,
    ioapic_device_tube: Tube,
) -> base::Result<WhpxSplitIrqChip> {
    info!("Creating WHPX split irqchip");
    WhpxSplitIrqChip::new(
        vm.try_clone()?,
        ioapic_device_tube,
        None, // ioapic_pins
    )
}

fn create_userspace_irq_chip<Vm, Vcpu>(
    vcpu_count: usize,
    ioapic_device_tube: Tube,
) -> base::Result<UserspaceIrqChip<Vcpu>>
where
    Vm: VmArch + 'static,
    Vcpu: VcpuArch + 'static,
{
    info!("Creating userspace irqchip");
    let irq_chip =
        UserspaceIrqChip::new(vcpu_count, ioapic_device_tube, /*ioapic_pins:*/ None)?;
    Ok(irq_chip)
}

pub fn get_default_hypervisor() -> Option<HypervisorKind> {
    // The ordering here matters from most preferable to the least.
    #[cfg(feature = "whpx")]
    match hypervisor::whpx::Whpx::is_enabled() {
        true => return Some(HypervisorKind::Whpx),
        false => warn!("Whpx not enabled."),
    };

    #[cfg(feature = "haxm")]
    if get_cpu_manufacturer() == CpuManufacturer::Intel {
        // Make sure Haxm device can be opened before selecting it.
        match Haxm::new() {
            Ok(_) => return Some(HypervisorKind::Ghaxm),
            Err(e) => warn!("Cannot initialize HAXM: {}", e),
        };
    }

    #[cfg(feature = "gvm")]
    // Make sure Gvm device can be opened before selecting it.
    match Gvm::new() {
        Ok(_) => return Some(HypervisorKind::Gvm),
        Err(e) => warn!("Cannot initialize GVM: {}", e),
    };

    None
}

fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(
            File::open(initrd_path).with_exit_context(Exit::OpenInitrd, || {
                format!("failed to open initrd {}", initrd_path.display())
            })?,
        )
    } else {
        None
    };

    let vm_image = match cfg.executable_path {
        Some(Executable::Kernel(ref kernel_path)) => VmImage::Kernel(
            File::open(kernel_path).with_exit_context(Exit::OpenKernel, || {
                format!("failed to open kernel image {}", kernel_path.display(),)
            })?,
        ),
        Some(Executable::Bios(ref bios_path)) => {
            VmImage::Bios(File::open(bios_path).with_exit_context(Exit::OpenBios, || {
                format!("failed to open bios {}", bios_path.display())
            })?)
        }
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
        cpu_frequencies: BTreeMap::new(),
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
        hv_cfg: hypervisor::Config {
            protection_type: cfg.protection_type,
        },
        vm_image,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| {
                File::open(x).with_exit_context(Exit::OpenAndroidFstab, || {
                    format!("failed to open android fstab file {}", x.display())
                })
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
                SDT::from_file(path).with_exit_context(Exit::OpenAcpiTable, || {
                    format!("failed to open ACPI file {}", path.display())
                })
            })
            .collect::<Result<Vec<SDT>>>()?,
        rt_cpus: cfg.rt_cpus.clone(),
        delay_rt: cfg.delay_rt,
        no_i8042: cfg.no_i8042,
        no_rtc: cfg.no_rtc,
        host_cpu_topology: cfg.host_cpu_topology,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        force_s2idle: cfg.force_s2idle,
        itmt: false,
        pvm_fw: None,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        pci_low_start: cfg.pci_low_start,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        pcie_ecam: cfg.pcie_ecam,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        oem_strings: cfg.oem_strings.clone(),
        dynamic_power_coefficient: cfg.dynamic_power_coefficient.clone(),
    })
}

// Enum that allows us to assign a variable to what is essentially a &dyn IrqChipArch.
enum WindowsIrqChip<V: VcpuArch> {
    Userspace(UserspaceIrqChip<V>),
    #[cfg(feature = "gvm")]
    Gvm(GvmIrqChip),
    #[cfg(feature = "whpx")]
    WhpxSplit(WhpxSplitIrqChip),
}

impl<V: VcpuArch> WindowsIrqChip<V> {
    // Convert our enum to a &mut dyn IrqChipArch
    fn as_mut(&mut self) -> &mut dyn IrqChipArch {
        match self {
            WindowsIrqChip::Userspace(i) => i,
            #[cfg(feature = "gvm")]
            WindowsIrqChip::Gvm(i) => i,
            #[cfg(feature = "whpx")]
            WindowsIrqChip::WhpxSplit(i) => i,
        }
    }
}

/// Storage for the VM TSC offset for each vcpu. Stored in a static because the tracing thread will
/// need access to it when tracing is enabled.
static TSC_OFFSETS: once_cell::sync::Lazy<sync::Mutex<Vec<Option<u64>>>> =
    once_cell::sync::Lazy::new(|| sync::Mutex::new(Vec::new()));

/// Save the TSC offset for a particular vcpu.
///
/// After setting the TSC offset for a vcpu, this function checks the standard deviation of offsets
/// for all the VCPUs and logs this information. If the TSC offsets differ too much between vcpus
/// it can cause clock issues in the guest.
pub fn save_vcpu_tsc_offset(offset: u64, vcpu_id: usize) {
    let offsets_copy = {
        let mut offsets = TSC_OFFSETS.lock();
        // make sure offsets vec is large enough before inserting
        let newlen = std::cmp::max(offsets.len(), vcpu_id + 1);
        offsets.resize(newlen, None);
        offsets[vcpu_id] = Some(offset);

        offsets.clone()
    };

    // do statistics on a clone of the offsets so we don't hold up other vcpus at this point
    info!(
        "TSC offset standard deviation is: {}",
        standard_deviation(
            &offsets_copy
                .iter()
                .filter(|x| x.is_some())
                .map(|x| x.unwrap() as u128)
                .collect::<Vec<u128>>()
        )
    );
}

/// Get the TSC offset of any vcpu. It will pick the first non-None offset it finds in TSC_OFFSETS.
#[cfg(feature = "perfetto")]
pub fn get_vcpu_tsc_offset() -> u64 {
    if let Some(offset) = TSC_OFFSETS.lock().iter().flatten().next() {
        return *offset;
    }
    0
}

/// Callback that is registered with tracing crate, and will be called by the tracing thread when
/// tracing is enabled or disabled. Regardless of whether tracing is being enabled or disabled for
/// a given category or instance, we just emit a clock snapshot that maps the guest TSC to the
/// host TSC. Redundant snapshots should not be a problem for perfetto.
#[cfg(feature = "perfetto")]
fn set_tsc_clock_snapshot() {
    let freq = match devices::tsc::tsc_frequency() {
        Err(e) => {
            error!(
                "Could not determine tsc frequency, unable to snapshot tsc offset: {}",
                e
            );
            return;
        }
        Ok(freq) => freq,
    };

    // The offset is host-guest tsc value
    let offset = get_vcpu_tsc_offset();
    // Safe because _rdtsc takes no arguments;
    let host_tsc = unsafe { std::arch::x86_64::_rdtsc() };
    perfetto::snapshot_clock(perfetto::ClockSnapshot::new(
        // Technically our multiplier should be freq/1_000_000_000, but perfetto doesn't
        // support floating point multipliers yet. So for now we set the freq in Hz and rely
        // on the merge tool to fix it.
        perfetto::Clock::new(
            perfetto::BuiltinClock::Tsc as u32,
            host_tsc.wrapping_add(offset),
        )
        .set_multiplier(freq as u64),
        perfetto::Clock::new(
            // The host builtin clock ids are all offset from the guest ids by
            // HOST_GUEST_CLOCK_ID_OFFSET when the traces are merged. Because this snapshot
            // contains both a guest and host clock, we need to offset it before merge.
            perfetto::BuiltinClock::Tsc as u32 + cros_tracing::HOST_GUEST_CLOCK_ID_OFFSET,
            host_tsc,
        )
        .set_multiplier(freq as u64),
    ));
}

/// Launches run_config for the broker, reading configuration from a TubeTransporter.
pub fn run_config_for_broker(raw_tube_transporter: RawDescriptor) -> Result<ExitState> {
    // Safe because we know that raw_transport_tube is valid (passed by inheritance), and that
    // the blocking & framing modes are accurate because we create them ourselves in the broker.
    let tube_transporter =
        unsafe { TubeTransporterReader::from_raw_descriptor(raw_tube_transporter) };

    let mut tube_data_list = tube_transporter
        .read_tubes()
        .exit_context(Exit::TubeTransporterInit, "failed to init tube transporter")?;

    let bootstrap_tube = tube_data_list
        .get_tube(TubeToken::Bootstrap)
        .exit_context(Exit::TubeFailure, "failed to get bootstrap tube")?;

    let mut cfg: Config = bootstrap_tube
        .recv::<Config>()
        .exit_context(Exit::TubeFailure, "failed to read bootstrap tube")?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube
        .recv::<CommonChildStartupArgs>()
        .exit_context(Exit::TubeFailure, "failed to read bootstrap tube")?;
    let _child_cleanup = common_child_setup(startup_args).exit_context(
        Exit::CommonChildSetupError,
        "failed to perform common child setup",
    )?;

    cfg.broker_shutdown_event = Some(
        bootstrap_tube
            .recv::<Event>()
            .exit_context(Exit::TubeFailure, "failed to read bootstrap tube")?,
    );
    let crash_tube_map = bootstrap_tube
        .recv::<HashMap<ProcessType, Vec<SendTube>>>()
        .exit_context(Exit::TubeFailure, "failed to read bootstrap tube")?;
    #[cfg(feature = "crash-report")]
    crash_report::set_crash_tube_map(crash_tube_map);

    let BrokerTubes {
        vm_evt_wrtube,
        vm_evt_rdtube,
    } = bootstrap_tube
        .recv::<BrokerTubes>()
        .exit_context(Exit::TubeFailure, "failed to read bootstrap tube")?;

    run_config_inner(cfg, vm_evt_wrtube, vm_evt_rdtube)
}

pub fn run_config(cfg: Config) -> Result<ExitState> {
    let _raise_timer_resolution = enable_high_res_timers()
        .exit_context(Exit::EnableHighResTimer, "failed to enable high res timer")?;

    // There is no broker when using run_config(), so the vm_evt tubes need to be created.
    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    run_config_inner(cfg, vm_evt_wrtube, vm_evt_rdtube)
}

fn create_guest_memory(
    components: &VmComponents,
    hypervisor: &impl Hypervisor,
) -> Result<GuestMemory> {
    let guest_mem_layout = Arch::guest_memory_layout(components, hypervisor).exit_context(
        Exit::GuestMemoryLayout,
        "failed to create guest memory layout",
    )?;
    GuestMemory::new_with_options(&guest_mem_layout)
        .exit_context(Exit::CreateGuestMemory, "failed to create guest memory")
}

fn run_config_inner(
    cfg: Config,
    vm_evt_wrtube: SendTube,
    vm_evt_rdtube: RecvTube,
) -> Result<ExitState> {
    product::setup_common_metric_invariants(&cfg);

    #[cfg(feature = "perfetto")]
    cros_tracing::add_per_trace_callback(set_tsc_clock_snapshot);

    let components: VmComponents = setup_vm_components(&cfg)?;

    #[allow(unused_mut)]
    let mut hypervisor = cfg
        .hypervisor
        .or_else(get_default_hypervisor)
        .exit_context(Exit::NoDefaultHypervisor, "no enabled hypervisor")?;

    #[cfg(feature = "whpx")]
    if hypervisor::whpx::Whpx::is_enabled() {
        // If WHPX is enabled, no other hypervisor can be used, so just override it
        hypervisor = HypervisorKind::Whpx;
    }

    match hypervisor {
        #[cfg(feature = "haxm")]
        HypervisorKind::Haxm | HypervisorKind::Ghaxm => {
            if hypervisor == HypervisorKind::Haxm {
                set_use_ghaxm(false);
            }
            info!("Creating HAXM ghaxm={}", get_use_ghaxm());
            let haxm = Haxm::new()?;
            let guest_mem = create_guest_memory(&components, &haxm)?;
            let vm = create_haxm_vm(haxm, guest_mem, &cfg.kernel_log_file)?;
            let (ioapic_host_tube, ioapic_device_tube) =
                Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
            let irq_chip = create_userspace_irq_chip::<HaxmVm, HaxmVcpu>(
                components.vcpu_count,
                ioapic_device_tube,
            )?;
            run_vm::<HaxmVcpu, HaxmVm>(
                cfg,
                components,
                vm,
                WindowsIrqChip::Userspace(irq_chip).as_mut(),
                Some(ioapic_host_tube),
                vm_evt_wrtube,
                vm_evt_rdtube,
            )
        }
        #[cfg(feature = "whpx")]
        HypervisorKind::Whpx => {
            let apic_emulation_supported =
                Whpx::check_whpx_feature(WhpxFeature::LocalApicEmulation)
                    .exit_context(Exit::WhpxSetupError, "failed to set up whpx")?;

            let no_smt = cfg.no_smt;

            // Default to WhpxSplitIrqChip if it's supported because it's more performant
            let irq_chip = cfg.irq_chip.unwrap_or(if apic_emulation_supported {
                IrqChipKind::Split
            } else {
                IrqChipKind::Userspace
            });

            // Both WHPX irq chips use a userspace IOAPIC
            let (ioapic_host_tube, ioapic_device_tube) =
                Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

            info!("Creating Whpx");
            let whpx = Whpx::new()?;
            let guest_mem = create_guest_memory(&components, &whpx)?;
            let vm = create_whpx_vm(
                whpx,
                guest_mem,
                components.vcpu_count,
                no_smt,
                apic_emulation_supported && irq_chip == IrqChipKind::Split,
                cfg.force_calibrated_tsc_leaf,
                vm_evt_wrtube
                    .try_clone()
                    .expect("could not clone vm_evt_wrtube"),
            )?;

            let mut irq_chip = match irq_chip {
                IrqChipKind::Kernel => unimplemented!("Kernel irqchip mode not supported by WHPX"),
                IrqChipKind::Split => {
                    if !apic_emulation_supported {
                        panic!(
                            "split irqchip specified but your WHPX version does not support \
                               local apic emulation"
                        );
                    }
                    WindowsIrqChip::WhpxSplit(create_whpx_split_irq_chip(&vm, ioapic_device_tube)?)
                }
                IrqChipKind::Userspace => {
                    WindowsIrqChip::Userspace(create_userspace_irq_chip::<WhpxVm, WhpxVcpu>(
                        components.vcpu_count,
                        ioapic_device_tube,
                    )?)
                }
            };
            run_vm::<WhpxVcpu, WhpxVm>(
                cfg,
                components,
                vm,
                irq_chip.as_mut(),
                Some(ioapic_host_tube),
                vm_evt_wrtube,
                vm_evt_rdtube,
            )
        }
        #[cfg(feature = "gvm")]
        HypervisorKind::Gvm => {
            info!("Creating GVM");
            let gvm = Gvm::new()?;
            let guest_mem = create_guest_memory(&components, &gvm)?;
            let vm = create_gvm_vm(gvm, guest_mem)?;
            let ioapic_host_tube;
            let mut irq_chip = match cfg.irq_chip.unwrap_or(IrqChipKind::Kernel) {
                IrqChipKind::Split => unimplemented!("Split irqchip mode not supported by GVM"),
                IrqChipKind::Kernel => {
                    ioapic_host_tube = None;
                    WindowsIrqChip::Gvm(create_gvm_irq_chip(&vm, components.vcpu_count)?)
                }
                IrqChipKind::Userspace => {
                    let (host_tube, ioapic_device_tube) =
                        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
                    ioapic_host_tube = Some(host_tube);
                    WindowsIrqChip::Userspace(create_userspace_irq_chip::<GvmVm, GvmVcpu>(
                        components.vcpu_count,
                        ioapic_device_tube,
                    )?)
                }
            };
            run_vm::<GvmVcpu, GvmVm>(
                cfg,
                components,
                vm,
                irq_chip.as_mut(),
                ioapic_host_tube,
                vm_evt_wrtube,
                vm_evt_rdtube,
            )
        }
    }
}

#[cfg(any(feature = "haxm", feature = "gvm", feature = "whpx"))]
fn run_vm<Vcpu, V>(
    #[allow(unused_mut)] mut cfg: Config,
    #[allow(unused_mut)] mut components: VmComponents,
    mut vm: V,
    irq_chip: &mut dyn IrqChipArch,
    ioapic_host_tube: Option<Tube>,
    vm_evt_wrtube: SendTube,
    vm_evt_rdtube: RecvTube,
) -> Result<ExitState>
where
    Vcpu: VcpuArch + 'static,
    V: VmArch + 'static,
{
    let vm_memory_size_mb = components.memory_size / (1024 * 1024);
    let mut control_tubes = Vec::new();
    let mut irq_control_tubes = Vec::new();
    // Create one control tube per disk.
    let mut disk_device_tubes = Vec::new();
    let mut disk_host_tubes = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_tube, disk_device_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        disk_host_tubes.push(disk_host_tube);
        disk_device_tubes.push(disk_device_tube);
    }

    if let Some(ioapic_host_tube) = ioapic_host_tube {
        irq_control_tubes.push(ioapic_host_tube);
    }

    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_tube, balloon_device_tube) = if cfg.balloon {
        let (balloon_host_tube, balloon_device_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        (Some(balloon_host_tube), Some(balloon_device_tube))
    } else {
        (None, None)
    };
    // The balloon device also needs a tube to communicate back to the main process to
    // handle remapping memory dynamically.
    let dynamic_mapping_device_tube = if cfg.balloon {
        let (dynamic_mapping_host_tube, dynamic_mapping_device_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        control_tubes.push(TaggedControlTube::VmMemory(dynamic_mapping_host_tube));
        Some(dynamic_mapping_device_tube)
    } else {
        None
    };

    // PvClock gets a tube for handling suspend/resume requests from the main thread.
    let (pvclock_host_tube, pvclock_device_tube) = if cfg.pvclock {
        let (host, device) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        (Some(host), Some(device))
    } else {
        (None, None)
    };

    let gralloc =
        RutabagaGralloc::new().exit_context(Exit::CreateGralloc, "failed to create gralloc")?;

    let pstore_size = components.pstore.as_ref().map(|pstore| pstore.size as u64);
    let mut sys_allocator = SystemAllocator::new(
        Arch::get_system_allocator_config(&vm),
        pstore_size,
        &cfg.mmio_address_ranges,
    )
    .context("failed to create system allocator")?;

    #[allow(unused_mut)]
    let mut ac97_host_tubes = Vec::new();
    #[allow(unused_mut)]
    let mut ac97_device_tubes = Vec::new();
    #[cfg(feature = "audio")]
    for _ in &cfg.ac97_parameters {
        let (ac97_host_tube, ac97_device_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        ac97_host_tubes.push(ac97_host_tube);
        ac97_device_tubes.push(ac97_device_tube);
    }

    // Allocate the ramoops region first.
    let ramoops_region = match &components.pstore {
        Some(pstore) => Some(
            arch::pstore::create_memory_region(
                &mut vm,
                sys_allocator.reserved_region().unwrap(),
                pstore,
            )
            .exit_context(
                Exit::Pstore,
                format!("failed to allocate pstore region {:?}", &components.pstore),
            )?,
        ),
        None => None,
    };

    let init_balloon_size = components
        .memory_size
        .checked_sub(cfg.init_memory.map_or(components.memory_size, |m| {
            m.checked_mul(1024 * 1024).unwrap_or(u64::MAX)
        }))
        .context("failed to calculate init balloon size")?;

    let tsc_state = devices::tsc::tsc_state().exit_code(Exit::TscCalibrationFailed)?;
    let tsc_sync_mitigations = get_tsc_sync_mitigations(&tsc_state, components.vcpu_count);

    if tsc_state.core_grouping.size() > 1 {
        // Host TSCs are not in sync, log a metric about it.
        warn!(
            "Host TSCs are not in sync, applying the following mitigations: {:?}",
            tsc_sync_mitigations
        );
        log_descriptor(
            MetricEventType::TscCoresOutOfSync,
            // casting u64 as i64 is a no-op, so we don't lose any part of the bitmask
            tsc_state.core_grouping.core_grouping_bitmask() as i64,
        );
    }

    let product_args = product::get_run_control_args(&mut cfg);

    let virtio_snd_state_device_tube = create_snd_state_tube(&mut control_tubes)?;

    let (virtio_snd_host_mute_tube, virtio_snd_device_mute_tube) = create_snd_mute_tube_pair()?;

    let pci_devices = create_devices(
        &mut cfg,
        vm.get_memory(),
        &vm_evt_wrtube,
        &mut irq_control_tubes,
        &mut control_tubes,
        &mut disk_device_tubes,
        balloon_device_tube,
        pvclock_device_tube,
        dynamic_mapping_device_tube,
        /* inflate_tube= */ None,
        init_balloon_size,
        ac97_host_tubes,
        tsc_state.frequency,
        virtio_snd_state_device_tube,
        virtio_snd_device_mute_tube,
    )?;

    let mut vcpu_ids = Vec::new();

    let windows = Arch::build_vm::<V, Vcpu>(
        components,
        &vm_evt_wrtube,
        &mut sys_allocator,
        &cfg.serial_parameters,
        None,
        (cfg.battery_config.as_ref().map(|t| t.type_), None),
        vm,
        ramoops_region,
        pci_devices,
        irq_chip,
        &mut vcpu_ids,
        cfg.dump_device_tree_blob.clone(),
        /*debugcon_jail=*/ None,
        None,
    )
    .exit_context(Exit::BuildVm, "the architecture failed to build the vm")?;

    #[cfg(feature = "stats")]
    let stats = if cfg.exit_stats {
        Some(Arc::new(Mutex::new(StatisticsCollector::new())))
    } else {
        None
    };

    // Lower the token, locking the main process down to a stricter security policy.
    //
    // WARNING:
    //
    // Windows system calls can behave in unusual ways if they happen concurrently to the token
    // lowering. For example, access denied can happen if Tube pairs are created in another thread
    // (b/281108137), and lower_token happens right before the client pipe is connected. Tubes are
    // not privileged resources, but can be broken due to the token changing unexpectedly.
    //
    // We explicitly lower the token here and *then* call run_control to make it clear that any
    // resources that require a privileged token should be created on the main thread & passed into
    // run_control, to follow the correct order:
    // - Privileged resources are created.
    // - Token is lowered.
    // - Threads are spawned & may create more non-privileged resources (without fear of the token
    //   changing at an undefined time).
    //
    // Recommendation: If you find your code doesnt work in run_control because of the sandbox, you
    // should split any resource creation to before this token lowering & pass the resources into
    // run_control. Don't move the token lowering somewhere else without considering multi-threaded
    // effects.
    #[cfg(feature = "sandbox")]
    if sandbox::is_sandbox_target() {
        sandbox::TargetServices::get()
            .exit_code_from_err("failed to create sandbox")?
            .expect("Could not create sandbox!")
            .lower_token();
    }

    run_control(
        windows,
        sys_allocator,
        control_tubes,
        irq_control_tubes,
        vm_evt_rdtube,
        vm_evt_wrtube,
        cfg.broker_shutdown_event.take(),
        balloon_host_tube,
        pvclock_host_tube,
        disk_host_tubes,
        gralloc,
        #[cfg(feature = "stats")]
        stats,
        cfg.service_pipe_name,
        ac97_device_tubes,
        vm_memory_size_mb,
        cfg.host_cpu_topology,
        tsc_sync_mitigations,
        cfg.force_calibrated_tsc_leaf,
        product_args,
        virtio_snd_host_mute_tube,
        cfg.restore_path,
        cfg.socket_path,
        cfg.force_s2idle,
        cfg.suspended,
    )
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn create_config(test_dir: &TempDir) -> Config {
        let mut config = Config::default();

        let dummy_kernel_path = test_dir.path().join("dummy_kernel.txt");
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(&dummy_kernel_path)
            .expect("Could not open file!");
        config.executable_path = Some(Executable::Kernel(dummy_kernel_path));

        config
    }

    #[test]
    #[should_panic(expected = "Did not receive a bios or kernel")]
    fn setup_vm_components_panics_when_no_kernel_provided() {
        let mut config =
            create_config(&TempDir::new().expect("Could not create temporary directory!"));
        config.executable_path = None;
        let _ = setup_vm_components(&config);
    }

    #[test]
    fn setup_vm_components_stores_memory_in_bytes() {
        let tempdir = TempDir::new().expect("Could not create temporary directory!");
        let mut config = create_config(&tempdir);
        config.memory = Some(1);
        let vm_components = setup_vm_components(&config).expect("failed to setup vm components");
        assert_eq!(vm_components.memory_size, 1024 * 1024);
    }

    #[test]
    fn setup_vm_components_fails_when_memory_too_large() {
        let tempdir = TempDir::new().expect("Could not create temporary directory!");
        let mut config = create_config(&tempdir);
        // One mb more than a u64 can hold in bytes
        config.memory = Some((u64::MAX / 1024 / 1024) + 1);
        setup_vm_components(&config).err().expect("expected error");
    }
}
