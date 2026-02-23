// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::Mutex;
use std::thread;
use std::thread::JoinHandle;

use anyhow::anyhow;
use anyhow::Context;
use arch::LinuxArch;
use arch::VmComponents;
use arch::VmImage;
use base::debug;
use base::error;
use base::info;
use base::open_file_or_duplicate;
use base::syslog;
use base::syslog::LogArgs;
use base::syslog::LogConfig;
use base::EventToken;
use base::SendTube;
use base::Tube;
use base::VmEventType;
use base::WaitContext;
use base::ReadNotifier;
use devices::virtio;
use devices::virtio::NetParametersMode;
use devices::virtio::VirtioDevice;
use devices::Bus;
use devices::BusDeviceObj;
use devices::HvfIrqChip;
use devices::IrqChipAArch64;
use devices::IrqEdgeEvent;
use devices::IrqEventSource;
use hypervisor::hvf::Hvf;
use hypervisor::hvf::HvfVcpu;
use hypervisor::hvf::HvfVm;
use hypervisor::IoOperation;
use hypervisor::IoParams;
use hypervisor::ProtectionType;
use hypervisor::Vm;
use hypervisor::VcpuAArch64;
use hypervisor::VcpuExit;
use jail::FakeMinijailStub as Minijail;
use net_util::TapTCommon;
use vm_control::api::VmMemoryClient;
use vm_control::IrqSetup;
use vm_control::VmIrqRequest;
use vm_control::VmMemoryRegionState;
use vm_control::VmMemoryRequest;
use vm_memory::GuestMemory;

use crate::crosvm::config::Executable;
use crate::crosvm::sys::cmdline::Commands;
use crate::crosvm::sys::cmdline::DeviceSubcommand;
use crate::CommandStatus;
use crate::Config;

type Arch = aarch64::AArch64;

/// VM exit states for macOS.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExitState {
    Reset,
    Stop,
    Crash,
    GuestPanic,
    WatchdogReset,
}

/// Runs a single VCPU thread.
fn run_vcpu_thread(
    cpu_id: usize,
    mut vcpu: Box<dyn VcpuAArch64>,
    mmio_bus: Bus,
    vm_evt_wrtube: SendTube,
    start_barrier: Arc<Barrier>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{cpu_id}"))
        .spawn(move || {
            start_barrier.wait();

            let exit_state = vcpu_loop(cpu_id, vcpu.as_mut(), &mmio_bus);

            let event = match exit_state {
                ExitState::Stop => VmEventType::Exit,
                ExitState::Reset => VmEventType::Reset,
                ExitState::Crash => VmEventType::Crash,
                _ => VmEventType::Exit,
            };
            if let Err(e) = vm_evt_wrtube.send::<VmEventType>(&event) {
                error!("failed to send vm event from vcpu {}: {}", cpu_id, e);
            }
        })
        .expect("failed to spawn VCPU thread")
}

/// The inner VCPU run loop. Runs until the guest exits or an error occurs.
fn vcpu_loop(cpu_id: usize, vcpu: &mut (dyn VcpuAArch64 + '_), mmio_bus: &Bus) -> ExitState {
    let mut exit_count: u64 = 0;
    let mut hlt_count: u64 = 0;
    let mut intr_count: u64 = 0;
    loop {
        match vcpu.run() {
            Ok(VcpuExit::Mmio) => {
                exit_count += 1;
                if let Err(e) =
                    vcpu.handle_mmio(&mut |IoParams { address, operation }| {
                        if exit_count <= 20 || exit_count % 10000 == 0 {
                            info!("vcpu {}: MMIO #{} addr={:#x}", cpu_id, exit_count, address);
                        }
                        match operation {
                            IoOperation::Read(data) => {
                                mmio_bus.read(address, data);
                                Ok(())
                            }
                            IoOperation::Write(data) => {
                                mmio_bus.write(address, data);
                                Ok(())
                            }
                        }
                    })
                {
                    error!("vcpu {}: failed to handle mmio: {}", cpu_id, e);
                }
            }
            Ok(VcpuExit::Hlt) => {
                hlt_count += 1;
                if hlt_count <= 5 || hlt_count % 10000 == 0 {
                    info!("vcpu {}: HLT(WFI) #{}", cpu_id, hlt_count);
                }
                // Guest executed WFI/WFE - sleep briefly then continue
                thread::sleep(std::time::Duration::from_millis(1));
            }
            Ok(VcpuExit::Shutdown(_)) => {
                info!("vcpu {}: guest shutdown", cpu_id);
                return ExitState::Stop;
            }
            Ok(VcpuExit::SystemEventShutdown) => {
                info!("vcpu {}: system shutdown event", cpu_id);
                return ExitState::Stop;
            }
            Ok(VcpuExit::SystemEventReset) => {
                info!("vcpu {}: system reset event", cpu_id);
                return ExitState::Reset;
            }
            Ok(VcpuExit::Intr) => {
                intr_count += 1;
                if intr_count <= 5 || intr_count % 100000 == 0 {
                    debug!("vcpu {}: Intr #{}", cpu_id, intr_count);
                }
            }
            Ok(VcpuExit::Canceled) => {
                info!("vcpu {}: canceled", cpu_id);
                return ExitState::Stop;
            }
            Ok(VcpuExit::Exception) => {
                error!("vcpu {}: unhandled exception", cpu_id);
                return ExitState::Crash;
            }
            Ok(VcpuExit::InternalError) => {
                error!("vcpu {}: internal error", cpu_id);
                return ExitState::Crash;
            }
            Ok(exit) => {
                error!("vcpu {}: unexpected exit: {:?}", cpu_id, exit);
            }
            Err(e) => {
                error!("vcpu {}: run error: {}", cpu_id, e);
                return ExitState::Crash;
            }
        }
    }
}

#[derive(EventToken)]
enum Token {
    VmEvent,
}

/// Create the VmComponents from configuration.
fn setup_vm_components(cfg: &Config) -> anyhow::Result<VmComponents> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(
            open_file_or_duplicate(initrd_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open initrd {}", initrd_path.display()))?,
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
        _ => return Err(anyhow!("no kernel or BIOS path specified")),
    };

    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let memory_size = cfg
        .memory
        .unwrap_or(256)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("requested memory size too large"))?;

    let android_fstab = cfg
        .android_fstab
        .as_ref()
        .map(|p| {
            open_file_or_duplicate(p, OpenOptions::new().read(true))
                .context("failed to open android fstab")
        })
        .transpose()?;

    Ok(VmComponents {
        #[cfg(all(target_arch = "x86_64", unix))]
        ac_adapter: false,
        acpi_sdts: Vec::new(),
        android_fstab,
        boot_cpu: cfg.boot_cpu,
        bootorder_fw_cfg_blob: Vec::new(),
        #[cfg(target_arch = "x86_64")]
        break_linux_pci_config_io: false,
        cpu_capacity: cfg.cpu_capacity.clone(),
        cpu_clusters: cfg.cpu_clusters.clone(),
        #[cfg(all(
            target_arch = "aarch64",
            any(target_os = "android", target_os = "linux")
        ))]
        cpu_frequencies: BTreeMap::new(),
        delay_rt: false,
        dev_pm: None,
        dynamic_power_coefficient: BTreeMap::new(),
        extra_kernel_params: cfg.params.clone(),
        #[cfg(target_arch = "x86_64")]
        force_s2idle: false,
        fw_cfg_enable: false,
        fw_cfg_parameters: Vec::new(),
        host_cpu_topology: false,
        hugepages: false,
        hv_cfg: hypervisor::Config {
            #[cfg(target_arch = "aarch64")]
            mte: false,
            protection_type: ProtectionType::Unprotected,
            #[cfg(all(target_os = "android", target_arch = "aarch64"))]
            ffa: false,
            force_disable_readonly_mem: false,
        },
        initrd_image,
        itmt: false,
        memory_size,
        no_i8042: true,
        no_rtc: true,
        no_smt: cfg.no_smt,
        #[cfg(all(
            target_arch = "aarch64",
            any(target_os = "android", target_os = "linux")
        ))]
        normalized_cpu_ipc_ratios: BTreeMap::new(),
        pci_config: Default::default(),
        pflash_block_size: 0,
        pflash_image: None,
        pstore: None,
        pvm_fw: None,
        rt_cpus: Default::default(),
        #[cfg(target_arch = "x86_64")]
        smbios: Default::default(),
        smccc_trng: false,
        #[cfg(target_arch = "aarch64")]
        sve_config: Default::default(),
        swiotlb: None,
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        vcpu_count,
        #[cfg(all(
            target_arch = "aarch64",
            any(target_os = "android", target_os = "linux")
        ))]
        vcpu_domain_paths: BTreeMap::new(),
        #[cfg(all(
            target_arch = "aarch64",
            any(target_os = "android", target_os = "linux")
        ))]
        vcpu_domains: BTreeMap::new(),
        #[cfg(any(target_os = "android", target_os = "linux"))]
        vfio_platform_pm: false,
        #[cfg(all(
            target_arch = "aarch64",
            any(target_os = "android", target_os = "linux")
        ))]
        virt_cpufreq_v2: false,
        vm_image,
    })
}

/// Create virtio devices from configuration.
///
/// Returns a vector of (device, jail) pairs to pass to build_vm, along with
/// the host-side tubes that need to be serviced.
fn create_virtio_devices(
    cfg: &Config,
    guest_mem: &GuestMemory,
) -> anyhow::Result<(
    Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
    Vec<Tube>,      // IRQ host tubes
    Vec<Tube>,      // VM memory host tubes
)> {
    let mut devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)> = Vec::new();
    let mut irq_host_tubes = Vec::new();
    let mut vm_memory_host_tubes = Vec::new();

    // Create block devices
    for disk in &cfg.disks {
        let disk_image = disk.open().context("failed to open disk image")?;
        let features = virtio::base_features(ProtectionType::Unprotected);
        let block_dev = virtio::BlockAsync::new(
            features,
            disk_image,
            disk,
            None, // control_tube
            None, // queue_size
            None, // num_queues
        )
        .context("failed to create block device")?;

        let (msi_host_tube, msi_device_tube) =
            Tube::pair().context("failed to create MSI tube")?;
        let (ioevent_host_tube, ioevent_device_tube) =
            Tube::pair().context("failed to create ioevent tube")?;
        let (_vm_control_host_tube, vm_control_device_tube) =
            Tube::pair().context("failed to create vm control tube")?;

        let pci_dev = devices::virtio::VirtioPciDevice::new(
            guest_mem.clone(),
            Box::new(block_dev) as Box<dyn VirtioDevice>,
            msi_device_tube,
            false, // disable_intx
            None,  // shared_memory_vm_memory_client
            VmMemoryClient::new(ioevent_device_tube),
            vm_control_device_tube,
        )
        .context("failed to create virtio PCI device for block")?;

        devices.push((Box::new(pci_dev) as Box<dyn BusDeviceObj>, None));
        irq_host_tubes.push(msi_host_tube);
        vm_memory_host_tubes.push(ioevent_host_tube);

        info!("Created virtio-blk device for {}", disk.path.display());
    }

    // Create net devices
    for net_param in &cfg.net {
        let vq_pairs = net_param.vq_pairs.unwrap_or(1);

        // Create the vmnet tap device
        let tap = <net_util::sys::macos::Tap as TapTCommon>::new(true, vq_pairs > 1)
            .context("failed to create vmnet tap")?;
        let mac = match &net_param.mode {
            NetParametersMode::RawConfig { mac, .. } => Some(*mac),
            NetParametersMode::TapName { mac, .. } => *mac,
            NetParametersMode::TapFd { mac, .. } => *mac,
        };

        let features = virtio::base_features(ProtectionType::Unprotected);
        let net_dev = virtio::Net::new(
            features,
            tap,
            vq_pairs,
            mac,
            net_param.packed_queue,
            net_param.pci_address,
            net_param.mrg_rxbuf,
        )
        .context("failed to create virtio-net device")?;

        // Create tube pairs for PCI device infrastructure
        let (msi_host_tube, msi_device_tube) =
            Tube::pair().context("failed to create MSI tube")?;
        let (ioevent_host_tube, ioevent_device_tube) =
            Tube::pair().context("failed to create ioevent tube")?;
        let (_vm_control_host_tube, vm_control_device_tube) =
            Tube::pair().context("failed to create vm control tube")?;

        let pci_dev = devices::virtio::VirtioPciDevice::new(
            guest_mem.clone(),
            Box::new(net_dev) as Box<dyn VirtioDevice>,
            msi_device_tube,
            false, // disable_intx
            None,  // shared_memory_vm_memory_client (net has no shared memory)
            VmMemoryClient::new(ioevent_device_tube),
            vm_control_device_tube,
        )
        .context("failed to create virtio PCI device for net")?;

        devices.push((Box::new(pci_dev) as Box<dyn BusDeviceObj>, None));
        irq_host_tubes.push(msi_host_tube);
        vm_memory_host_tubes.push(ioevent_host_tube);

        info!("Created vmnet virtio-net device");
    }

    Ok((devices, irq_host_tubes, vm_memory_host_tubes))
}

/// Spawn a thread to handle IRQ tube requests (MSI allocation, routing, etc.)
fn spawn_irq_handler_thread(
    irq_tubes: Vec<Tube>,
    irq_chip: Box<dyn devices::IrqChipAArch64>,
    sys_allocator: Arc<Mutex<resources::SystemAllocator>>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("crosvm_irq_handler".into())
        .spawn(move || {
            let mut irq_chip = irq_chip;

            #[derive(EventToken)]
            enum IrqToken {
                Tube { id: usize },
                IrqFd { index: usize },
            }

            let wait_ctx: WaitContext<IrqToken> = WaitContext::new()
                .expect("failed to create IRQ handler WaitContext");

            for (id, tube) in irq_tubes.iter().enumerate() {
                wait_ctx
                    .add(tube.get_read_notifier(), IrqToken::Tube { id })
                    .expect("failed to add IRQ tube to WaitContext");
            }

            // Also watch for IRQ events from the chip
            let irq_event_tokens = irq_chip
                .irq_event_tokens()
                .expect("failed to get IRQ event tokens");
            for (index, _source, evt) in &irq_event_tokens {
                wait_ctx
                    .add(evt, IrqToken::IrqFd { index: *index })
                    .expect("failed to add IRQ event to WaitContext");
            }

            loop {
                let events = match wait_ctx.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("IRQ handler wait failed: {}", e);
                        break;
                    }
                };

                for event in events.iter().filter(|e| e.is_readable) {
                    match event.token {
                        IrqToken::Tube { id } => {
                            let tube = &irq_tubes[id];
                            match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = request.execute(
                                        |setup| match setup {
                                            IrqSetup::Event(irq, ev, device_id, queue_id, device_name) => {
                                                let irq_evt = IrqEdgeEvent::from_event(ev.try_clone()?);
                                                let source = IrqEventSource {
                                                    device_id,
                                                    queue_id,
                                                    device_name,
                                                };
                                                if let Some(event_index) = irq_chip
                                                    .as_irq_chip_mut()
                                                    .register_edge_irq_event(irq, &irq_evt, source)?
                                                {
                                                    if let Err(e) = wait_ctx.add(
                                                        ev,
                                                        IrqToken::IrqFd { index: event_index },
                                                    ) {
                                                        error!("failed to add IrqFd to wait context: {}", e);
                                                        return Err(e);
                                                    }
                                                }
                                                Ok(())
                                            }
                                            IrqSetup::Route(route) => {
                                                irq_chip.as_irq_chip_mut().route_irq(route)
                                            }
                                            IrqSetup::UnRegister(irq, ev) => {
                                                let irq_evt = IrqEdgeEvent::from_event(ev.try_clone()?);
                                                irq_chip
                                                    .as_irq_chip_mut()
                                                    .unregister_edge_irq_event(irq, &irq_evt)
                                            }
                                        },
                                        &mut sys_allocator.lock().unwrap(),
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmIrqResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    // Disconnected means device shut down, which is normal
                                    if !matches!(e, base::TubeError::Disconnected) {
                                        error!("failed to recv VmIrqRequest: {}", e);
                                    }
                                    return;
                                }
                            }
                        }
                        IrqToken::IrqFd { index } => {
                            if let Err(e) = irq_chip.as_irq_chip_mut().service_irq_event(index) {
                                error!("failed to signal IRQ {}: {}", index, e);
                            }
                        }
                    }
                }
            }
        })
        .expect("failed to spawn IRQ handler thread")
}

/// Spawn a thread to handle VM memory requests (ioevent registration, etc.)
fn spawn_vm_memory_handler_thread(
    vm_memory_tubes: Vec<Tube>,
    mut vm: HvfVm,
    sys_allocator: Arc<Mutex<resources::SystemAllocator>>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("crosvm_vm_memory".into())
        .spawn(move || {
            #[derive(EventToken)]
            enum MemToken {
                Tube { id: usize },
            }

            let wait_ctx: WaitContext<MemToken> = WaitContext::new()
                .expect("failed to create VM memory handler WaitContext");

            for (id, tube) in vm_memory_tubes.iter().enumerate() {
                wait_ctx
                    .add(tube.get_read_notifier(), MemToken::Tube { id })
                    .expect("failed to add VM memory tube to WaitContext");
            }

            let mut gralloc = rutabaga_gfx::RutabagaGralloc::new(
                rutabaga_gfx::RutabagaGrallocBackendFlags::new(),
            )
            .expect("failed to create gralloc");
            let mut region_state: VmMemoryRegionState = Default::default();

            loop {
                let events = match wait_ctx.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("VM memory handler wait failed: {}", e);
                        break;
                    }
                };

                for event in events.iter().filter(|e| e.is_readable) {
                    match event.token {
                        MemToken::Tube { id } => {
                            let tube = &vm_memory_tubes[id];
                            match tube.recv::<VmMemoryRequest>() {
                                Ok(request) => {
                                    let response = request.execute(
                                        &mut vm,
                                        &mut sys_allocator.lock().unwrap(),
                                        &mut gralloc,
                                        None, // no IOMMU
                                        &mut region_state,
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmMemoryResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if !matches!(e, base::TubeError::Disconnected) {
                                        error!("failed to recv VmMemoryRequest: {}", e);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        })
        .expect("failed to spawn VM memory handler thread")
}

/// Run a VM with the given configuration.
pub fn run_config(cfg: Config) -> anyhow::Result<ExitState> {
    cfg.executable_path
        .as_ref()
        .ok_or_else(|| anyhow!("no kernel or BIOS path specified"))?;

    info!("Starting crosvm on macOS with HVF");

    // Step 1: Create the hypervisor
    let hvf = Hvf::new().context("failed to create HVF hypervisor")?;

    // Step 2: Set up VM components from config
    let components = setup_vm_components(&cfg)?;
    let arch_memory_layout = Arch::arch_memory_layout(&components)
        .context("failed to create arch memory layout")?;
    let guest_memory_layout =
        Arch::guest_memory_layout(&components, &arch_memory_layout, &hvf)
            .context("failed to create guest memory layout")?;

    let guest_mem = GuestMemory::new_with_options(&guest_memory_layout)
        .context("failed to create guest memory")?;

    // Step 3: Create the VM
    let vm = HvfVm::new(&hvf, guest_mem.clone(), components.hv_cfg)
        .context("failed to create HVF VM")?;

    // Step 4: Set up the system allocator
    let system_allocator_config =
        Arch::get_system_allocator_config(&vm, &arch_memory_layout);
    let mut system_allocator =
        resources::SystemAllocator::new(system_allocator_config, None, &[])
            .context("failed to create system allocator")?;

    // Step 5: Set up VM event tubes
    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    // Step 6: Create the IRQ chip
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let mut vcpu_ids: Vec<usize> = (0..vcpu_count).collect();
    let serial_parameters = cfg.serial_parameters.clone();

    let mut irq_chip =
        HvfIrqChip::new(vcpu_count).context("failed to create HVF IRQ chip")?;

    // Step 6.5: Create virtio devices (net, etc.)
    let (devices, irq_host_tubes, vm_memory_host_tubes) =
        create_virtio_devices(&cfg, &guest_mem)?;

    // Clone VM for the memory handler thread (before build_vm consumes it)
    let vm_for_memory_handler = vm
        .try_clone()
        .context("failed to clone HvfVm for memory handler")?;

    // Step 7: Build the VM (this creates devices, FDT, etc.)
    let linux = Arch::build_vm::<HvfVm, HvfVcpu>(
        components,
        &arch_memory_layout,
        &vm_evt_wrtube,
        &mut system_allocator,
        &serial_parameters,
        None, // serial_jail (no sandboxing on macOS)
        (None, None), // battery
        vm,
        None, // ramoops_region
        devices,
        &mut irq_chip,
        &mut vcpu_ids,
        None, // dump_device_tree_blob
        None, // debugcon_jail
        #[cfg(feature = "swap")]
        &mut None,
        None, // guest_suspended_cvar
        Vec::new(), // device_tree_overlays
        None, // fdt_position
        false, // no_pmu
    )
    .context("failed to build VM")?;

    // Step 7.5: Spawn handler threads for device tube communication
    let sys_allocator = Arc::new(Mutex::new(system_allocator));
    let mut handler_handles = Vec::new();

    if !irq_host_tubes.is_empty() {
        let irq_chip_clone = irq_chip
            .try_box_clone()
            .context("failed to clone IRQ chip for handler")?;
        handler_handles.push(spawn_irq_handler_thread(
            irq_host_tubes,
            irq_chip_clone,
            sys_allocator.clone(),
        ));
    }

    if !vm_memory_host_tubes.is_empty() {
        handler_handles.push(spawn_vm_memory_handler_thread(
            vm_memory_host_tubes,
            vm_for_memory_handler,
            sys_allocator.clone(),
        ));
    }

    // Step 8: Configure and start VCPU threads
    let vcpu_count = linux.vcpu_count;
    let start_barrier = Arc::new(Barrier::new(vcpu_count + 1));
    let mut vcpu_handles = Vec::new();

    if let Some(vcpus) = linux.vcpus {
        for (cpu_id, mut vcpu) in vcpus.into_iter().enumerate() {
            // Apply initial register state (PC, X0, PSTATE, etc.)
            let vcpu_init = linux.vcpu_init.get(cpu_id).cloned().unwrap_or_default();
            for (reg, value) in vcpu_init.regs.iter() {
                vcpu.set_one_reg(*reg, *value)
                    .with_context(|| format!("failed to set reg {:?} for vcpu {}", reg, cpu_id))?;
            }

            let handle = run_vcpu_thread(
                cpu_id,
                Box::new(vcpu),
                linux.mmio_bus.as_ref().clone(),
                vm_evt_wrtube.try_clone().context("failed to clone vm event tube")?,
                start_barrier.clone(),
            );
            vcpu_handles.push(handle);
        }
    }

    // Release all VCPUs to start running
    start_barrier.wait();
    info!("All {} VCPUs started", vcpu_count);

    // Step 9: Main event loop - wait for VM exit events
    let wait_ctx: WaitContext<Token> =
        WaitContext::build_with(&[(&vm_evt_rdtube, Token::VmEvent)])
            .context("failed to build WaitContext")?;

    let exit_state = 'outer: loop {
        let events = match wait_ctx.wait() {
            Ok(v) => v,
            Err(e) => {
                error!("WaitContext::wait error: {} - retrying", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::VmEvent => {
                    match vm_evt_rdtube.recv::<VmEventType>() {
                        Ok(VmEventType::Exit) => {
                            info!("VM requested exit");
                            break 'outer ExitState::Stop;
                        }
                        Ok(VmEventType::Reset) => {
                            info!("VM requested reset");
                            break 'outer ExitState::Reset;
                        }
                        Ok(VmEventType::Crash) => {
                            error!("VM crashed");
                            break 'outer ExitState::Crash;
                        }
                        Ok(VmEventType::Panic(_)) => {
                            error!("VM guest panic");
                            break 'outer ExitState::GuestPanic;
                        }
                        Ok(VmEventType::WatchdogReset) => {
                            info!("VM watchdog reset");
                            break 'outer ExitState::WatchdogReset;
                        }
                        Ok(_) => {
                            // Other event types - continue
                        }
                        Err(e) => {
                            error!("failed to recv vm event: {}", e);
                            break 'outer ExitState::Crash;
                        }
                    }
                }
            }
        }
    };

    // Wait for VCPU threads to finish
    for handle in vcpu_handles {
        let _ = handle.join();
    }

    info!("VM exited with state: {:?}", exit_state);
    Ok(exit_state)
}

pub(crate) fn start_device(_command: DeviceSubcommand) -> anyhow::Result<()> {
    Err(anyhow!("No device subcommands supported on macOS yet"))
}

pub(crate) fn cleanup() {}

pub(crate) fn run_command(_command: Commands, _log_args: LogArgs) -> anyhow::Result<()> {
    Err(anyhow!(
        "No platform-specific commands supported on macOS yet"
    ))
}

pub(crate) fn init_log(log_config: LogConfig, _cfg: &Config) -> anyhow::Result<()> {
    if let Err(e) = syslog::init_with(log_config) {
        eprintln!("failed to initialize syslog: {e}");
        return Err(anyhow!("failed to initialize syslog: {}", e));
    }
    Ok(())
}

pub(crate) fn error_to_exit_code(
    _res: &std::result::Result<CommandStatus, anyhow::Error>,
) -> i32 {
    1
}
