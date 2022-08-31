// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b:240716507): There is huge chunk for code which depends on haxm, whpx or gvm to be enabled but
// isn't marked so. Remove this when we do so.
#![allow(dead_code, unused_imports, unused_variables, unreachable_code)]

pub(crate) mod irq_wait;
pub(crate) mod main;
pub(crate) mod metrics;
#[cfg(not(feature = "crash-report"))]
mod panic_hook;
pub(crate) mod run_vcpu;

#[cfg(feature = "whpx")]
use std::arch::x86_64::__cpuid;
#[cfg(feature = "whpx")]
use std::arch::x86_64::__cpuid_count;
#[cfg(feature = "gpu")]
use std::collections::BTreeMap;
#[cfg(feature = "kiwi")]
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::iter;
use std::mem;
#[cfg(feature = "gpu")]
use std::num::NonZeroU8;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use acpi_tables::sdt::SDT;
#[cfg(all(feature = "kiwi", feature = "anti-tamper",))]
use anti_tamper::spawn_dedicated_anti_tamper_thread;
use anyhow::anyhow;
use anyhow::bail;
#[cfg(feature = "kiwi")]
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use arch::LinuxArch;
use arch::RunnableLinuxVm;
use arch::VirtioDeviceStub;
use arch::VmComponents;
use arch::VmImage;
use base::enable_high_res_timers;
use base::error;
#[cfg(feature = "kiwi")]
use base::give_foregrounding_permission;
use base::info;
use base::open_file;
use base::warn;
#[cfg(feature = "gpu")]
use base::BlockingMode;
use base::Event;
use base::EventToken;
#[cfg(feature = "gpu")]
use base::FramingMode;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::ReadNotifier;
use base::RecvTube;
use base::SendTube;
#[cfg(feature = "gpu")]
use base::StreamChannel;
use base::Tube;
use base::TubeError;
use base::VmEventType;
use base::WaitContext;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::tsc::get_tsc_sync_mitigations;
use devices::tsc::standard_deviation;
use devices::tsc::TscSyncMitigations;
use devices::virtio;
use devices::virtio::block::block::DiskOption;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonMode;
use devices::virtio::Console;
#[cfg(feature = "slirp")]
use devices::virtio::NetExt;
#[cfg(feature = "pvclock")]
use devices::virtio::PvClock;
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::BusDeviceObj;
#[cfg(feature = "gvm")]
use devices::GvmIrqChip;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use devices::IrqChip;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use devices::IrqChipAArch64 as IrqChipArch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::IrqChipX86_64 as IrqChipArch;
use devices::Minijail;
use devices::UserspaceIrqChip;
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::CpuConfigX86_64;
#[cfg(feature = "whpx")]
use hypervisor::Hypervisor;
#[cfg(feature = "whpx")]
use hypervisor::HypervisorCap;
#[cfg(feature = "whpx")]
use hypervisor::HypervisorX86_64;
use hypervisor::ProtectionType;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VcpuAArch64 as VcpuArch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::VcpuX86_64 as VcpuArch;
#[cfg(any(feature = "gvm", feature = "whpx"))]
use hypervisor::Vm;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VmAArch64 as VmArch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::VmX86_64 as VmArch;
use irq_wait::IrqWaitWorker;
#[cfg(not(feature = "crash-report"))]
pub(crate) use panic_hook::set_panic_hook;
use resources::SystemAllocator;
use run_vcpu::run_all_vcpus;
use run_vcpu::VcpuRunMode;
use rutabaga_gfx::RutabagaGralloc;
#[cfg(feature = "kiwi")]
use service_ipc::get_balloon_size;
#[cfg(feature = "kiwi")]
use service_ipc::request_utilities::prod::MessageFromService;
#[cfg(all(feature = "kiwi", feature = "anti-tamper"))]
use service_ipc::request_utilities::prod::MessageToService;
#[cfg(feature = "kiwi")]
use service_ipc::service_vm_state::ServiceVmState;
#[cfg(feature = "kiwi")]
use service_ipc::ServiceIpc;
use sync::Mutex;
use tube_transporter::TubeToken;
use tube_transporter::TubeTransporterReader;
#[cfg(feature = "kiwi")]
use vm_control::Ac97Control;
#[cfg(feature = "kiwi")]
use vm_control::BalloonControlCommand;
#[cfg(feature = "kiwi")]
use vm_control::GpuSendToMain;
#[cfg(feature = "kiwi")]
use vm_control::GpuSendToMain::MuteAc97;
#[cfg(feature = "kiwi")]
use vm_control::GpuSendToMain::SendToService;
#[cfg(feature = "kiwi")]
use vm_control::PvClockCommand;
#[cfg(feature = "kiwi")]
use vm_control::PvClockCommandResponse;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use vm_control::VmMemoryRequest;
use vm_control::VmRunMode;
use vm_memory::GuestMemory;
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
#[cfg(feature = "gpu")]
use crate::crosvm::config::TouchDeviceOption;
use crate::crosvm::sys::config::HypervisorKind;
#[cfg(any(feature = "gvm", feature = "whpx"))]
use crate::crosvm::sys::config::IrqChipKind;
use crate::crosvm::sys::windows::exit::Exit;
use crate::crosvm::sys::windows::exit::ExitContext;
use crate::crosvm::sys::windows::exit::ExitContextAnyhow;
#[cfg(feature = "stats")]
use crate::crosvm::sys::windows::stats::StatisticsCollector;
use crate::sys::windows::metrics::log_descriptor;
use crate::sys::windows::metrics::MetricEventType;

const DEFAULT_GUEST_CID: u64 = 3;

enum TaggedControlTube {
    // TODO: handle vm_control messages as they get added.
    #[allow(dead_code)]
    Vm(Tube),
    VmMemory(Tube),
    #[cfg(feature = "kiwi")]
    GpuServiceComm(Tube),
    #[cfg(feature = "kiwi")]
    GpuDeviceServiceComm(Tube),
}

pub enum ExitState {
    Reset,
    Stop,
    Crash,
    #[allow(dead_code)]
    GuestPanic,
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
        disk.id,
        Some(disk_device_tube),
    )
    .exit_context(Exit::BlockDeviceNew, "failed to create block device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_device(
    cfg: &Config,
    vm_evt_wrtube: &SendTube,
    gpu_device_tube: Tube,
    resource_bridges: Vec<Tube>,
    event_devices: Vec<EventDevice>,
    #[cfg(feature = "kiwi")] gpu_device_service_tube: Tube,
) -> DeviceResult {
    let gpu_parameters = cfg
        .gpu_parameters
        .as_ref()
        .expect("No GPU parameters provided in config!");
    let display_backends = vec![virtio::DisplayBackend::WinApi(
        (&gpu_parameters.display_params[0]).into(),
    )];
    let wndproc_thread = virtio::gpu::start_wndproc_thread(
        #[cfg(feature = "kiwi")]
        gpu_parameters.display_params[0]
            .gpu_main_display_tube
            .clone(),
        #[cfg(not(feature = "kiwi"))]
        None,
    )
    .expect("Failed to start wndproc_thread!");

    let features = virtio::base_features(cfg.protection_type);
    let dev = virtio::Gpu::new(
        vm_evt_wrtube
            .try_clone()
            .exit_context(Exit::CloneTube, "failed to clone tube")?,
        resource_bridges,
        display_backends,
        gpu_parameters,
        event_devices,
        /* external_blob= */ false,
        features,
        BTreeMap::new(),
        #[cfg(feature = "kiwi")]
        Some(gpu_device_service_tube),
        wndproc_thread,
    );

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
    let dev = virtio::new_multi_touch(
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
    let dev = virtio::new_mouse(idx, event_pipe, virtio::base_features(cfg.protection_type))
        .exit_context(Exit::InputDeviceNew, "failed to set up input device")?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: None,
    })
}

#[cfg(feature = "slirp")]
fn create_net_device(
    #[cfg(feature = "slirp-ring-capture")] slirp_capture_file: &Option<String>,
) -> DeviceResult {
    let dev = virtio::Net::<net_util::Slirp>::new_slirp(
        #[cfg(feature = "slirp-ring-capture")]
        slirp_capture_file,
    )
    .exit_context(Exit::NetDeviceNew, "failed to set up virtio networking")?;

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

#[allow(dead_code)] // TODO(b/234031017): balloon device startup gets stuck on Windows
#[cfg(feature = "balloon")]
fn create_balloon_device(
    cfg: &Config,
    balloon_device_tube: Tube,
    dynamic_mapping_device_tube: Tube,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
) -> DeviceResult {
    let dev = virtio::Balloon::new(
        virtio::base_features(cfg.protection_type),
        balloon_device_tube,
        dynamic_mapping_device_tube,
        inflate_tube,
        init_balloon_size,
        if cfg.strict_balloon {
            BalloonMode::Strict
        } else {
            BalloonMode::Relaxed
        },
        0,
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
    let dev = virtio::Vsock::new(
        cfg.cid.unwrap_or(DEFAULT_GUEST_CID),
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

#[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
fn create_virtio_devices(
    cfg: &mut Config,
    vm_evt_wrtube: &SendTube,
    gpu_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    _balloon_device_tube: Option<Tube>,
    pvclock_device_tube: Option<Tube>,
    _dynamic_mapping_device_tube: Option<Tube>,
    _inflate_tube: Option<Tube>,
    _init_balloon_size: u64,
    #[cfg(feature = "kiwi")] gpu_device_service_tube: Tube,
    tsc_frequency: u64,
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

    if let Some(tube) = pvclock_device_tube {
        #[cfg(feature = "pvclock")]
        devs.push(VirtioDeviceStub {
            dev: Box::new(PvClock::new(tsc_frequency, tube)),
            jail: None,
        });
    }

    devs.push(create_rng_device(cfg)?);

    #[cfg(feature = "slirp")]
    if let Some(net_vhost_user_tube) = cfg.net_vhost_user_tube.take() {
        devs.push(create_vhost_user_net_device(cfg, net_vhost_user_tube)?);
    } else {
        devs.push(create_net_device(
            #[cfg(feature = "slirp-ring-capture")]
            &cfg.slirp_capture_file,
        )?);
    }

    // TODO(b/234031017): balloon device startup gets stuck on Windows
    //if let (Some(balloon_device_tube), Some(dynamic_mapping_device_tube)) =
    //    (balloon_device_tube, dynamic_mapping_device_tube)
    //{
    //    devs.push(create_balloon_device(
    //        &cfg,
    //        balloon_device_tube,
    //        dynamic_mapping_device_tube,
    //        inflate_tube,
    //        init_balloon_size,
    //    )?);
    //}

    devs.push(create_vsock_device(cfg)?);

    #[cfg(feature = "gpu")]
    {
        let resource_bridges = Vec::<Tube>::new();
        let mut event_devices: Vec<EventDevice> = Vec::new();

        if !cfg.virtio_single_touch.is_empty() {
            unimplemented!("--single-touch is no longer supported. Use --multi-touch instead.");
        }

        for (idx, multi_touch_spec) in cfg.virtio_multi_touch.iter().enumerate() {
            let (event_device_pipe, virtio_input_pipe) =
                StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                    .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;

            devs.push(create_multi_touch_device(
                cfg,
                multi_touch_spec,
                virtio_input_pipe,
                idx as u32,
            )?);
            event_devices.push(EventDevice::touchscreen(event_device_pipe));
        }

        for (idx, _mouse_socket) in cfg.virtio_mice.iter().enumerate() {
            let (event_device_pipe, virtio_input_pipe) =
                StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                    .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;
            devs.push(create_mouse_device(cfg, virtio_input_pipe, idx as u32)?);
            event_devices.push(EventDevice::mouse(event_device_pipe));
        }

        let (event_device_pipe, virtio_input_pipe) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;

        let dev = virtio::new_keyboard(
            /* idx= */ 0,
            virtio_input_pipe,
            virtio::base_features(cfg.protection_type),
        )
        .exit_context(Exit::InputDeviceNew, "failed to set up input device")?;
        devs.push(VirtioDeviceStub {
            dev: Box::new(dev),
            jail: None,
        });
        event_devices.push(EventDevice::keyboard(event_device_pipe));

        devs.push(create_gpu_device(
            cfg,
            vm_evt_wrtube,
            gpu_device_tube,
            resource_bridges,
            event_devices,
            #[cfg(feature = "kiwi")]
            gpu_device_service_tube,
        )?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &mut Config,
    mem: &GuestMemory,
    exit_evt_wrtube: &SendTube,
    irq_control_tubes: &mut Vec<Tube>,
    control_tubes: &mut Vec<TaggedControlTube>,
    gpu_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    balloon_device_tube: Option<Tube>,
    pvclock_device_tube: Option<Tube>,
    dynamic_mapping_device_tube: Option<Tube>,
    inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    #[allow(unused)] ac97_device_tubes: Vec<Tube>,
    #[cfg(feature = "kiwi")] gpu_device_service_tube: Tube,
    tsc_frequency: u64,
) -> DeviceResult<Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>> {
    let stubs = create_virtio_devices(
        cfg,
        exit_evt_wrtube,
        gpu_device_tube,
        disk_device_tubes,
        balloon_device_tube,
        pvclock_device_tube,
        dynamic_mapping_device_tube,
        inflate_tube,
        init_balloon_size,
        #[cfg(feature = "kiwi")]
        gpu_device_service_tube,
        tsc_frequency,
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

        let dev = Box::new(
            VirtioPciDevice::new(
                mem.clone(),
                stub.dev,
                msi_device_tube,
                cfg.disable_virtio_intx,
                shared_memory_tube,
            )
            .exit_context(Exit::VirtioPciDev, "failed to create virtio pci dev")?,
        ) as Box<dyn BusDeviceObj>;
        pci_devices.push((dev, stub.jail));
    }

    #[cfg(feature = "audio")]
    if cfg.ac97_parameters.len() != ac97_device_tubes.len() {
        panic!(
            "{} Ac97 device(s) will be made, but only {} Ac97 device tubes are present.",
            cfg.ac97_parameters.len(),
            ac97_device_tubes.len()
        );
    }

    #[cfg(feature = "audio")]
    for (ac97_param, ac97_device_tube) in cfg
        .ac97_parameters
        .iter()
        .zip(ac97_device_tubes.into_iter())
    {
        let dev = Ac97Dev::try_new(mem.clone(), ac97_param.clone(), ac97_device_tube)
            .exit_context(Exit::CreateAc97, "failed to create ac97 device")?;
        pci_devices.push((Box::new(dev), None));
    }

    Ok(pci_devices)
}

#[cfg(feature = "kiwi")]
fn set_package_name(msg: &MessageFromService) {
    match msg {
        MessageFromService::HideWindow => {
            #[cfg(feature = "crash-report")]
            crash_report::set_package_name("");

            metrics::set_package_name("");
        }
        MessageFromService::ShowWindow(ref show) => {
            #[cfg(feature = "crash-report")]
            crash_report::set_package_name(&show.package_name);

            metrics::set_package_name(&show.package_name);
        }
        _ => {}
    }
}

#[cfg(feature = "kiwi")]
fn merge_session_invariants(serialized_session_invariants: &[u8]) {
    metrics::merge_session_invariants(serialized_session_invariants);
}

#[derive(Debug)]
struct PvClockError(String);

/// Sending a pvclock command to the pvclock device can be tricky because we need to wait for a
/// response from the pvclock device if it's running. But, it's possible that the device is not
/// setup yet (or never will be, because the guest doesn't support it). In that case, we want to
/// timeout on recv-ing a response, and to do that we need to do a wait_timeout on the Tube's
/// read_notifier.
#[cfg(feature = "pvclock")]
fn handle_pvclock_request(tube: &Option<Tube>, command: PvClockCommand) -> Result<()> {
    if let Some(ref tube) = tube {
        tube.send(&command)
            .with_context(|| format!("failed to send pvclock command {:?}", command))?;

        #[derive(EventToken)]
        enum Token {
            RecvReady,
        }

        let wait_ctx = WaitContext::build_with(&[(tube.get_read_notifier(), Token::RecvReady)])
            .context("failed to build pvclock wait context")?;

        let evts = wait_ctx
            .wait_timeout(std::time::Duration::from_millis(100))
            .context("failed to wait on pvclock wait context")?;

        ensure!(evts.len() > 0, "timed out waiting for pvclock response");

        let resp = tube
            .recv::<PvClockCommandResponse>()
            .context("failed to receive pvclock command response")?;

        if let PvClockCommandResponse::Err(e) = resp {
            bail!("pvclock encountered error on {:?}: {}", command, e);
        }
    }

    Ok(())
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
    mut gralloc: RutabagaGralloc,
    #[cfg(feature = "stats")] stats: Option<Arc<Mutex<StatisticsCollector>>>,
    #[cfg(feature = "kiwi")] service_pipe_name: Option<String>,
    ac97_host_tubes: Vec<Tube>,
    memory_size_mb: u64,
    host_cpu_topology: bool,
    tsc_sync_mitigations: TscSyncMitigations,
    force_calibrated_tsc_leaf: bool,
) -> Result<ExitState> {
    #[cfg(not(feature = "kiwi"))]
    {
        // These variable are not used in other configurations. Suppress warnings.
        let _ = balloon_host_tube;
        let _ = pvclock_host_tube;
        let _ = ac97_host_tubes;
        let _ = memory_size_mb;
    }

    #[derive(EventToken)]
    enum Token {
        VmEvent,
        BrokerShutdown,
        VmControl {
            index: usize,
        },
        #[cfg(feature = "kiwi")]
        ServiceIpc,
        #[cfg(feature = "kiwi")]
        ProtoIpc,
        #[cfg(all(feature = "kiwi", feature = "anti-tamper"))]
        AntiTamper,
    }

    #[cfg(feature = "kiwi")]
    // Note: We use anti_tamper::MAX_CHALLENGE_SIZE because it's the
    // largest message passed through the tube. Note the Tube buffer has
    // to accomodate the largest message because of b/223807352.
    let (ipc_main_loop_tube, ipc_service_ipc_tube) =
        Tube::pair_with_buffer_size(anti_tamper::MAX_CHALLENGE_SIZE)
            .expect("Could not create Tube::pair()!");

    #[cfg(feature = "kiwi")]
    let (proto_main_loop_tube, proto_service_ipc_tube) =
        base::ProtoTube::pair_with_buffer_size(anti_tamper::MAX_CHALLENGE_SIZE)
            .expect("Could not create Tube::pair()!");

    #[cfg(feature = "kiwi")]
    let _service_ipc = ServiceIpc::start_ipc_listening_loops(
        service_pipe_name,
        ipc_service_ipc_tube,
        #[cfg(feature = "kiwi")]
        proto_service_ipc_tube,
    );

    #[cfg(feature = "kiwi")]
    let mut service_vm_state = ServiceVmState::new();

    let sys_allocator_mutex = Arc::new(Mutex::new(sys_allocator));

    let exit_evt = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;

    // Create a separate thread to wait on IRQ events. This is a natural division
    // because IRQ interrupts have no dependencies on other events, and this lets
    // us avoid approaching the Windows WaitForMultipleObjects 64-object limit.
    let irq_join_handle = IrqWaitWorker::start(
        exit_evt
            .try_clone()
            .exit_context(Exit::CloneEvent, "failed to clone event")?,
        guest_os
            .irq_chip
            .try_box_clone()
            .exit_context(Exit::CloneEvent, "failed to clone irq chip")?,
        irq_control_tubes,
        sys_allocator_mutex.clone(),
    );

    let wait_ctx = WaitContext::build_with(&[
        (vm_evt_rdtube.get_read_notifier(), Token::VmEvent),
        #[cfg(feature = "kiwi")]
        (ipc_main_loop_tube.get_read_notifier(), Token::ServiceIpc),
        #[cfg(feature = "kiwi")]
        (proto_main_loop_tube.get_read_notifier(), Token::ProtoIpc),
    ])
    .exit_context(
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
            #[cfg(feature = "kiwi")]
            TaggedControlTube::GpuServiceComm(tube) => {
                wait_ctx
                    .add(tube.get_read_notifier(), Token::VmControl { index })
                    .exit_context(
                        Exit::WaitContextAdd,
                        "failed to add trigger to wait context",
                    )?;
            }
            #[cfg(feature = "kiwi")]
            TaggedControlTube::GpuDeviceServiceComm(tube) => {
                wait_ctx
                    .add(tube.get_read_notifier(), Token::VmControl { index })
                    .exit_context(
                        Exit::WaitContextAdd,
                        "failed to add trigger to wait context",
                    )?;
            }
            // TODO(nkgold): as new control tubes are added, we'll need to add support for them
            _ => (),
        }
    }

    let vcpus: Vec<Option<_>> = match guest_os.vcpus.take() {
        Some(vec) => vec.into_iter().map(|vcpu| Some(vcpu)).collect(),
        None => iter::repeat_with(|| None)
            .take(guest_os.vcpu_count)
            .collect(),
    };

    #[cfg(all(feature = "kiwi", feature = "anti-tamper", not(feature = "kiwi")))]
    let (anti_tamper_main_thread_tube, anti_tamper_dedicated_thread_tube) =
        Tube::pair_with_buffer_size(anti_tamper::MAX_CHALLENGE_SIZE)
            .expect("Could not create Tube::pair()!");

    #[cfg(all(feature = "anti-tamper", feature = "kiwi"))]
    let (anti_tamper_main_thread_tube, anti_tamper_dedicated_thread_tube) =
        base::ProtoTube::pair_with_buffer_size(anti_tamper::MAX_CHALLENGE_SIZE)
            .expect("Could not create Tube::pair()!");

    #[cfg(all(feature = "kiwi", feature = "anti-tamper",))]
    if let Err(_e) = wait_ctx.add(
        anti_tamper_main_thread_tube.get_read_notifier(),
        Token::AntiTamper,
    ) {
        #[cfg(debug_assertions)]
        error!("Failed to add anti-tamper tube to wait_ctx: {}", _e);
    }

    #[cfg(all(feature = "kiwi", feature = "anti-tamper",))]
    spawn_dedicated_anti_tamper_thread(anti_tamper_dedicated_thread_tube);

    #[cfg(feature = "sandbox")]
    if sandbox::is_sandbox_target() {
        sandbox::TargetServices::get()
            .exit_context(Exit::SandboxError, "failed to create sandbox")?
            .expect("Could not create sandbox!")
            .lower_token();
    }

    let vcpu_boxes: Arc<Mutex<Vec<Box<dyn VcpuArch>>>> = Arc::new(Mutex::new(Vec::new()));
    let run_mode_arc = Arc::new(VcpuRunMode::default());
    let vcpu_threads = run_all_vcpus(
        vcpus,
        vcpu_boxes.clone(),
        &guest_os,
        &exit_evt,
        &vm_evt_wrtube,
        &pvclock_host_tube,
        #[cfg(feature = "stats")]
        &stats,
        host_cpu_topology,
        run_mode_arc.clone(),
        tsc_sync_mitigations,
        force_calibrated_tsc_leaf,
    )?;
    let mut exit_state = ExitState::Stop;

    // TODO: udam b/142733266 (sandboxing) registerwaitforsingleobject to wait on
    // child processes when they exit
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
            match event.token {
                Token::VmEvent => match vm_evt_rdtube.recv::<VmEventType>() {
                    Ok(vm_event) => {
                        match vm_event {
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
                            VmEventType::Panic(_) => {
                                error!("got pvpanic event. this event is not expected on Windows.");
                            }
                        }
                        break 'poll;
                    }
                    Err(e) => {
                        warn!("failed to recv VmEvent: {}", e);
                    }
                },
                Token::BrokerShutdown => {
                    info!("main loop got broker shutdown event");
                    break 'poll;
                }
                #[allow(clippy::collapsible_match)]
                Token::VmControl { index } => {
                    if let Some(tube) = control_tubes.get(index) {
                        #[allow(clippy::single_match)]
                        match tube {
                            TaggedControlTube::VmMemory(tube) => {
                                match tube.recv::<VmMemoryRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(
                                            &mut guest_os.vm,
                                            &mut sys_allocator_mutex.lock(),
                                            &mut gralloc,
                                            None,
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
                            #[cfg(feature = "kiwi")]
                            TaggedControlTube::GpuServiceComm(tube)
                            | TaggedControlTube::GpuDeviceServiceComm(tube) => {
                                match tube.recv::<GpuSendToMain>() {
                                    Ok(request) => {
                                        #[cfg(feature = "kiwi")]
                                        {
                                            match request {
                                                SendToService(service_request) => {
                                                    if let Err(e) = ipc_main_loop_tube.send(
                                                        &service_vm_state
                                                            .update_gpu_state_and_generate_message_to_service(&service_request),
                                                    ) {
                                                        error!(
                                                            "Failed to send message to ServiceIpc: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                                MuteAc97(mute) => {
                                                    for ac97_host_tube in &ac97_host_tubes {
                                                        ac97_host_tube
                                                            .send(&Ac97Control::Mute(mute))
                                                            .expect("Could not send mute message!");
                                                    }
                                                    service_vm_state.update_audio_state(mute);
                                                    if let Err(e) = ipc_main_loop_tube.send(
                                                        &service_vm_state
                                                            .generate_send_state_message(),
                                                    ) {
                                                        error!(
                                                            "Failed to send message to ServiceIpc: {}",
                                                            e
                                                        );
                                                    }

                                                }
                                            }
                                        }
                                        #[cfg(not(feature = "kiwi"))]
                                        {
                                            info!("Dropping message: {:?}", request);
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Error when receiving message from GpuServiceComm or GpuDeviceServiceComm tube: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            _ => (),
                            // TODO: handle vm_control messages.
                            /* TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        disk_host_tubes,
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control tube changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'poll;
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
                            }, */
                        }
                    }
                }
                #[cfg(feature = "kiwi")]
                Token::ProtoIpc => {
                    anti_tamper::forward_security_challenge(
                        &proto_main_loop_tube,
                        &anti_tamper_main_thread_tube,
                    );
                }
                // For handling service to crosvm messages. At this point, it is up to the dev how
                // they want to get the datagram to their component. It's recommended to use
                // Tubes if it can't be sent directly.
                #[cfg(feature = "kiwi")]
                Token::ServiceIpc => match ipc_main_loop_tube.recv::<MessageFromService>() {
                    Ok(request) => match request {
                        MessageFromService::ShowWindow(_)
                        | MessageFromService::HideWindow
                        | MessageFromService::Shutdown
                        | MessageFromService::MouseInputMode(_) => {
                            set_package_name(&request);
                            for control_tube in &control_tubes {
                                if let TaggedControlTube::GpuServiceComm(tube) = &control_tube {
                                    if let Err(e) =
                                        tube.send::<ServiceSendToGpu>(&request.try_into().expect(
                                            "Could not convert to ServiceSendToGpu request!",
                                        ))
                                    {
                                        error!("Failed to send message to GPU display: {}", e);
                                    }
                                    break;
                                }
                            }
                        }
                        MessageFromService::SetVmMemorySize(balloon_request) => {
                            info!(
                                "Service requested balloon adjustment, requested vm size: {}mb",
                                balloon_request.get_vm_memory_size_mb()
                            );
                            if let Some(ref balloon_host_tube) = balloon_host_tube {
                                if let Err(e) =
                                    balloon_host_tube.send(&BalloonControlCommand::Adjust {
                                        num_bytes: get_balloon_size(
                                            memory_size_mb,
                                            &balloon_request,
                                        ),
                                    })
                                {
                                    error!("Failed to modify balloon size - tube closed: {}", e);
                                }
                            } else {
                                error!("Failed to modify balloon size - balloon disabled");
                            }
                        }
                        MessageFromService::Suspend => {
                            info!("Received suspend request from the service");
                            // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
                            run_mode_arc.set_and_notify(VmRunMode::Suspending);

                            // Force all vcpus to exit from the hypervisor
                            for vcpu in vcpu_boxes.lock().iter() {
                                vcpu.set_immediate_exit(true);
                            }
                            guest_os.irq_chip.kick_halted_vcpus();

                            #[cfg(feature = "pvclock")]
                            handle_pvclock_request(&pvclock_host_tube, PvClockCommand::Suspend)
                                .unwrap_or_else(|e| {
                                    error!("Error handling pvclock suspend: {:?}", e)
                                });
                        }
                        MessageFromService::Resume => {
                            info!("Received resume request from the service");
                            #[cfg(feature = "pvclock")]
                            handle_pvclock_request(&pvclock_host_tube, PvClockCommand::Resume)
                                .unwrap_or_else(|e| {
                                    error!("Error handling pvclock resume: {:?}", e)
                                });

                            // Make sure any immediate exit bits are disabled
                            for vcpu in vcpu_boxes.lock().iter() {
                                vcpu.set_immediate_exit(false);
                            }

                            run_mode_arc.set_and_notify(VmRunMode::Running);
                        }
                        #[cfg(any(not(feature = "anti-tamper"), feature = "kiwi"))]
                        MessageFromService::ReceiveSecurityChallenge(_) => {}
                        #[cfg(all(feature = "anti-tamper", not(feature = "kiwi")))]
                        MessageFromService::ReceiveSecurityChallenge(security_challenge) => {
                            if let Err(_e) = anti_tamper_main_thread_tube.send(&security_challenge)
                            {
                                #[cfg(debug_assertions)]
                                error!(
                                    "Failed to send challenge program to anti-tamper thread: {}",
                                    _e
                                );
                            }
                        }
                        // Receive a mute request when the service receives lock/unlock screen event. The
                        // mute request should only be received if the window is NOT hidden (the service
                        // is responsible for that).
                        MessageFromService::AudioState(set_audio_state_request) => {
                            for ac97_host_tube in &ac97_host_tubes {
                                ac97_host_tube
                                    .send(&Ac97Control::Mute(set_audio_state_request.get_is_mute()))
                                    .expect("Could not send mute message!");
                            }
                            service_vm_state
                                .update_audio_state(set_audio_state_request.get_is_mute());

                            if let Err(e) = ipc_main_loop_tube
                                .send(&service_vm_state.generate_send_state_message())
                            {
                                error!("Failed to send message to ServiceIpc: {}", e);
                            }
                        }
                        MessageFromService::GetForegroundingPermission(
                            foregrounding_permission_request,
                        ) => {
                            // Perform best-effort, but do not block on failure
                            // TODO(b/205917759): Move this to gpu process
                            let mut result = false;
                            if let Err(e) = give_foregrounding_permission(
                                foregrounding_permission_request.get_process_id(),
                            ) {
                                error!("Failed to give foregrounding permission: {}", e);
                            } else {
                                result = true;
                            }

                            if let Err(e) = ipc_main_loop_tube.send(
                                &MessageToService::SendForegroundingPermissionResult(result.into()),
                            ) {
                                // Log, but otherwise ignore failures to send as they are
                                // handleable and non-fatal.
                                error!(
                                    "Failed to send foregrounding permission result to the service: {}",
                                    e
                                );
                            }
                        }
                        MessageFromService::MergeSessionInvariants(session_invariants_request) => {
                            let serialized_session_invariants =
                                session_invariants_request.get_serialized_session_invariants();
                            merge_session_invariants(serialized_session_invariants);
                        }

                        MessageFromService::SetAuthToken(set_auth_token_request) => {
                            metrics::set_auth_token(set_auth_token_request.get_auth_token());
                        }
                        MessageFromService::UploadCrashReport => {
                            #[cfg(feature = "crash-report")]
                            crash_report::upload_crash_report("anr");

                            #[cfg(not(feature = "crash-report"))]
                            info!("Dropping UploadCrashReport message");
                        }
                        MessageFromService::SystemHealthRequest => {
                            // Reply back with an empty report as there are no system health metrics
                            // to report yet.
                            if let Err(e) =
                                ipc_main_loop_tube.send(&MessageToService::SendSystemHealthReport())
                            {
                                #[cfg(debug_assertions)]
                                error!("Failed to send system health report to the service: {}", e);
                            }
                        }
                    },
                    Err(_e) => {}
                },
                #[cfg(all(feature = "kiwi", feature = "anti-tamper"))]
                Token::AntiTamper => anti_tamper::forward_security_signal(
                    &anti_tamper_main_thread_tube,
                    &ipc_main_loop_tube,
                ),
            }
        }
        for event in events.iter().filter(|e| e.is_hungup) {
            match event.token {
                Token::VmEvent | Token::BrokerShutdown => {}
                #[allow(unused_variables)]
                Token::VmControl { index } => {
                    // TODO: handle vm control messages as they get ported.
                    // It's possible more data is readable and buffered while the tube is hungup,
                    // so don't delete the tube from the poll context until we're sure all the
                    // data is read.
                    /*match control_tubes
                        .get(index)
                        .map(|s| s.as_ref().get_readable_bytes())
                    {
                        Some(Ok(0)) | Some(Err(_)) => vm_control_indices_to_remove.push(index),
                        Some(Ok(x)) => info!("control index {} has {} bytes readable", index, x),
                        _ => {}
                    }*/
                }
                #[cfg(feature = "kiwi")]
                Token::ProtoIpc => {}
                #[cfg(feature = "kiwi")]
                Token::ServiceIpc => {}
                #[cfg(all(feature = "kiwi", feature = "anti-tamper"))]
                Token::AntiTamper => {}
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserved correct indexes as each element is removed.
        //vm_control_indices_to_remove.sort_unstable_by(|a, b| b.cmp(a));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            control_tubes.swap_remove(index);
            /*if let Some(tube) = control_tubes.get(index) {
                wait_ctx
                    .modify(
                        tube, Token::VmControl { index },
                        EventType::Read
                    )
                    .exit_context(Exit::WaitContextAdd, "failed to add trigger to wait context")?;
            }*/
        }
    }

    // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
    run_mode_arc.set_and_notify(VmRunMode::Exiting);

    // Force all vcpus to exit from the hypervisor
    for vcpu in vcpu_boxes.lock().iter() {
        vcpu.set_immediate_exit(true);
    }

    let mut res = Ok(exit_state);
    guest_os.irq_chip.kick_halted_vcpus();
    let _ = exit_evt.write(1);
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

    // This cancels all the outstanding and any future blocking operations.
    // TODO(b/196911556): Shutdown executor for cleaner shutdown. Given we are using global, for a
    // cleaner shutdown we have to call disarm so that all the incoming requests are run and are
    // cancelled. If we call shutdown all blocking threads will go away and incoming operations
    // won't be scheduled to run and will be dropped leading to panic. I think ideal place to call
    // shutdown is when we drop non-global executor.
    cros_async::unblock_disarm();

    let _ = irq_join_handle.join();

    #[cfg(feature = "stats")]
    if let Some(stats) = stats {
        println!("Statistics Collected:\n{}", stats.lock());
        println!("Statistics JSON:\n{}", stats.lock().json());
    }

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control tubes are closed when this function exits.
    mem::drop(guest_os);

    res
}

#[cfg(feature = "gvm")]
const GVM_MINIMUM_VERSION: GvmVersion = GvmVersion {
    major: 1,
    minor: 4,
    patch: 1,
};

#[cfg(feature = "gvm")]
fn create_gvm(mem: GuestMemory) -> Result<GvmVm> {
    info!("Creating GVM");
    let gvm = Gvm::new()?;
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
fn create_haxm(mem: GuestMemory, kernel_log_file: &Option<String>) -> Result<HaxmVm> {
    info!("Creating HAXM ghaxm={}", get_use_ghaxm());
    let haxm = Haxm::new()?;
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
fn create_whpx(
    mem: GuestMemory,
    cpu_count: usize,
    no_smt: bool,
    apic_emulation: bool,
    force_calibrated_tsc_leaf: bool,
) -> Result<WhpxVm> {
    info!("Creating Whpx");
    let whpx = Whpx::new()?;

    let cpu_config = CpuConfigX86_64::new(
        force_calibrated_tsc_leaf,
        false, /* host_cpu_topology */
        false, /* enable_hwp */
        false, /* enable_pnp_data */
        no_smt,
        false, /* itmt */
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

    let vm = WhpxVm::new(&whpx, cpu_count, mem, cpuid, apic_emulation)
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

pub fn get_default_hypervisor() -> Result<HypervisorKind> {
    // The ordering here matters from most preferable to the least.
    #[cfg(feature = "whpx")]
    match hypervisor::whpx::Whpx::is_enabled() {
        true => return Ok(HypervisorKind::Whpx),
        false => warn!("Whpx not enabled."),
    };
    #[cfg(feature = "haxm")]
    if get_cpu_manufacturer() == CpuManufacturer::Intel {
        // Make sure Haxm device can be opened before selecting it.
        match Haxm::new() {
            Ok(_) => return Ok(HypervisorKind::Ghaxm),
            Err(e) => warn!("Cannot initialize HAXM: {}", e),
        };
    }
    #[cfg(feature = "gvm")]
    // Make sure Gvm device can be opened before selecting it.
    match Gvm::new() {
        Ok(_) => return Ok(HypervisorKind::Gvm),
        Err(e) => warn!("Cannot initialize GVM: {}", e),
    };
    bail!("no hypervisor enabled!");
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
        dmi_path: cfg.dmi_path.clone(),
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
#[cfg(feature = "cperfetto")]
pub fn get_vcpu_tsc_offset() -> u64 {
    for offset in TSC_OFFSETS.lock().iter() {
        if let Some(offset) = offset {
            return *offset;
        }
    }
    0
}

/// Callback that is registered with tracing crate, and will be called by the tracing thread when
/// tracing is enabled or disabled. Regardless of whether tracing is being enabled or disabled for
/// a given category or instance, we just emit a clock snapshot that maps the guest TSC to the
/// host TSC. Redundant snapshots should not be a problem for perfetto.
#[cfg(feature = "cperfetto")]
fn set_tsc_clock_snapshot() {
    let freq = match devices::tsc_frequency() {
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
            perfetto::BuiltinClock::Tsc as u32 + tracing::HOST_GUEST_CLOCK_ID_OFFSET,
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

    run_config_inner(cfg)
}

pub fn run_config(cfg: Config) -> Result<ExitState> {
    let _raise_timer_resolution = enable_high_res_timers()
        .exit_context(Exit::EnableHighResTimer, "failed to enable high res timer")?;
    run_config_inner(cfg)
}

fn run_config_inner(cfg: Config) -> Result<ExitState> {
    #[cfg(feature = "kiwi")]
    {
        let use_vulkan = if cfg!(feature = "gpu") {
            match &cfg.gpu_parameters {
                Some(params) => Some(params.use_vulkan),
                None => None,
            }
        } else {
            None
        };
        anti_tamper::setup_common_metric_invariants(
            &&cfg.product_version,
            &cfg.product_channel,
            &use_vulkan,
        );
    }

    tracing::init();
    #[cfg(feature = "cperfetto")]
    tracing::add_per_trace_callback(set_tsc_clock_snapshot);

    let components: VmComponents = setup_vm_components(&cfg)?;

    let guest_mem_layout = Arch::guest_memory_layout(&components).exit_context(
        Exit::GuestMemoryLayout,
        "failed to create guest memory layout",
    )?;
    let guest_mem = GuestMemory::new(&guest_mem_layout)
        .exit_context(Exit::CreateGuestMemory, "failed to create guest memory")?;

    let default_hypervisor = get_default_hypervisor()
        .exit_context(Exit::NoDefaultHypervisor, "no enabled hypervisor")?;
    #[allow(unused_mut)]
    let mut hypervisor = cfg.hypervisor.unwrap_or(default_hypervisor);

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
            let vm = create_haxm(guest_mem, &cfg.kernel_log_file)?;
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

            let vm = create_whpx(
                guest_mem,
                components.vcpu_count,
                no_smt,
                apic_emulation_supported && irq_chip == IrqChipKind::Split,
                cfg.force_calibrated_tsc_leaf,
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
            )
        }
        #[cfg(feature = "gvm")]
        HypervisorKind::Gvm => {
            let vm = create_gvm(guest_mem)?;
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
            run_vm::<GvmVcpu, GvmVm>(cfg, components, vm, irq_chip.as_mut(), ioapic_host_tube)
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
    let (gpu_host_tube, gpu_device_tube) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmMemory(gpu_host_tube));

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

    #[cfg(feature = "kiwi")]
    {
        if cfg.service_pipe_name.is_some() {
            let (gpu_main_host_tube, gpu_main_display_tube) =
                Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
            control_tubes.push(TaggedControlTube::GpuServiceComm(gpu_main_host_tube));
            let mut gpu_parameters = cfg
                .gpu_parameters
                .as_mut()
                .expect("missing GpuParameters in config");
            gpu_parameters.display_params.gpu_main_display_tube =
                Some(Arc::new(Mutex::new(gpu_main_display_tube)));
        }
    };

    // Create a ServiceComm tube to pass to the gpu device
    #[cfg(feature = "kiwi")]
    let gpu_device_service_tube = {
        let (gpu_device_service_tube, gpu_device_service_host_tube) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        control_tubes.push(TaggedControlTube::GpuDeviceServiceComm(
            gpu_device_service_host_tube,
        ));
        gpu_device_service_tube
    };

    let gralloc =
        RutabagaGralloc::new().exit_context(Exit::CreateGralloc, "failed to create gralloc")?;

    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;
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
            .exit_context(Exit::Pstore, "failed to allocate pstore region")?,
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

    let pci_devices = create_devices(
        &mut cfg,
        vm.get_memory(),
        &vm_evt_wrtube,
        &mut irq_control_tubes,
        &mut control_tubes,
        gpu_device_tube,
        &mut disk_device_tubes,
        balloon_device_tube,
        pvclock_device_tube,
        dynamic_mapping_device_tube,
        /* inflate_tube= */ None,
        init_balloon_size,
        ac97_host_tubes,
        #[cfg(feature = "kiwi")]
        gpu_device_service_tube,
        tsc_state.frequency,
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
        /*debugcon_jail=*/ None,
        None,
    )
    .exit_context(Exit::BuildVm, "the architecture failed to build the vm")?;

    let _render_node_host = ();

    #[cfg(feature = "stats")]
    let stats = if cfg.exit_stats {
        Some(Arc::new(Mutex::new(StatisticsCollector::new())))
    } else {
        None
    };

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
        gralloc,
        #[cfg(feature = "stats")]
        stats,
        #[cfg(feature = "kiwi")]
        cfg.service_pipe_name,
        ac97_device_tubes,
        vm_memory_size_mb,
        cfg.host_cpu_topology,
        tsc_sync_mitigations,
        cfg.force_calibrated_tsc_leaf,
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
