// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod android;
pub mod fdt;
pub mod pstore;
pub mod serial;

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;

use acpi_tables::aml::Aml;
use acpi_tables::sdt::SDT;
use base::{syslog, AsRawDescriptor, AsRawDescriptors, Event, Tube};
use devices::virtio::VirtioDevice;
use devices::{
    BarRange, Bus, BusDevice, BusDeviceObj, BusError, BusResumeDevice, HotPlugBus, IrqChip,
    PciAddress, PciBridge, PciDevice, PciDeviceError, PciInterruptPin, PciRoot, ProxyDevice,
    SerialHardware, SerialParameters, VfioPlatformDevice,
};
use hypervisor::{IoEventAddress, ProtectionType, Vm};
use minijail::Minijail;
use remain::sorted;
use resources::{MmioType, SystemAllocator, SystemAllocatorConfig};
use sync::Mutex;
use thiserror::Error;
use vm_control::{BatControl, BatteryType, PmResource};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use gdbstub_arch::x86::reg::X86_64CoreRegs as GdbStubRegs;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{Hypervisor as HypervisorArch, VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {
    devices::IrqChipX86_64 as IrqChipArch,
    hypervisor::{HypervisorX86_64 as HypervisorArch, VcpuX86_64 as VcpuArch, VmX86_64 as VmArch},
};

pub use serial::{
    add_serial_devices, get_serial_cmdline, set_default_serial_parameters, GetSerialCmdlineError,
    SERIAL_ADDR,
};

pub enum VmImage {
    Kernel(File),
    Bios(File),
}

#[derive(Clone)]
pub struct Pstore {
    pub path: PathBuf,
    pub size: u32,
}

/// Mapping of guest VCPU threads to host CPU cores.
#[derive(Clone, Debug, PartialEq)]
pub enum VcpuAffinity {
    /// All VCPU threads will be pinned to the same set of host CPU cores.
    Global(Vec<usize>),
    /// Each VCPU may be pinned to a set of host CPU cores.
    /// The map key is a guest VCPU index, and the corresponding value is the set of
    /// host CPU indices that the VCPU thread will be allowed to run on.
    /// If a VCPU index is not present in the map, its affinity will not be set.
    PerVcpu(BTreeMap<usize, Vec<usize>>),
}

/// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
/// create a `RunnableLinuxVm`.
pub struct VmComponents {
    pub memory_size: u64,
    pub swiotlb: Option<u64>,
    pub vcpu_count: usize,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub cpu_clusters: Vec<Vec<usize>>,
    pub cpu_capacity: BTreeMap<usize, u32>,
    pub no_smt: bool,
    pub hugepages: bool,
    pub vm_image: VmImage,
    pub android_fstab: Option<File>,
    pub pstore: Option<Pstore>,
    pub initrd_image: Option<File>,
    pub extra_kernel_params: Vec<String>,
    pub acpi_sdts: Vec<SDT>,
    pub rt_cpus: Vec<usize>,
    pub delay_rt: bool,
    pub protected_vm: ProtectionType,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    pub gdb: Option<(u32, Tube)>, // port and control tube.
    pub dmi_path: Option<PathBuf>,
    pub no_legacy: bool,
    pub host_cpu_topology: bool,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub force_s2idle: bool,
    #[cfg(feature = "direct")]
    pub direct_gpe: Vec<u32>,
}

/// Holds the elements needed to run a Linux VM. Created by `build_vm`.
pub struct RunnableLinuxVm<V: VmArch, Vcpu: VcpuArch> {
    pub vm: V,
    pub vcpu_count: usize,
    /// If vcpus is None, then it's the responsibility of the vcpu thread to create vcpus.
    /// If it's Some, then `build_vm` already created the vcpus.
    pub vcpus: Option<Vec<Vcpu>>,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub no_smt: bool,
    pub irq_chip: Box<dyn IrqChipArch>,
    pub has_bios: bool,
    pub io_bus: Arc<Bus>,
    pub mmio_bus: Arc<Bus>,
    pub pid_debug_label_map: BTreeMap<u32, String>,
    pub suspend_evt: Event,
    pub rt_cpus: Vec<usize>,
    pub delay_rt: bool,
    pub bat_control: Option<BatControl>,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    pub gdb: Option<(u32, Tube)>,
    pub pm: Option<Arc<Mutex<dyn PmResource>>>,
    /// Devices to be notified before the system resumes from the S3 suspended state.
    pub resume_notify_devices: Vec<Arc<Mutex<dyn BusResumeDevice>>>,
    pub root_config: Arc<Mutex<PciRoot>>,
    pub hotplug_bus: Vec<Arc<Mutex<dyn HotPlugBus>>>,
}

/// The device and optional jail.
pub struct VirtioDeviceStub {
    pub dev: Box<dyn VirtioDevice>,
    pub jail: Option<Minijail>,
}

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    type Error: StdError;

    /// Returns a Vec of the valid memory addresses as pairs of address and length. These should be
    /// used to configure the `GuestMemory` structure for the platform.
    ///
    /// # Arguments
    ///
    /// * `components` - Parts used to determine the memory layout.
    fn guest_memory_layout(
        components: &VmComponents,
    ) -> std::result::Result<Vec<(GuestAddress, u64)>, Self::Error>;

    /// Gets the configuration for a new `SystemAllocator` that fits the given `Vm`'s memory layout.
    ///
    /// This is the per-architecture template for constructing the `SystemAllocator`. Platform
    /// agnostic modifications may be made to this configuration, but the final `SystemAllocator`
    /// will be at least as strict as this configuration.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine to be used as a template for the `SystemAllocator`.
    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig;

    /// Takes `VmComponents` and generates a `RunnableLinuxVm`.
    ///
    /// # Arguments
    ///
    /// * `components` - Parts to use to build the VM.
    /// * `exit_evt` - Event used by sub-devices to request that crosvm exit because guest
    ///     wants to stop/shut down.
    /// * `reset_evt` - Event used by sub-devices to request that crosvm exit because guest
    ///     requested reset.
    /// * `system_allocator` - Allocator created by this trait's implementation of
    ///   `get_system_allocator_config`.
    /// * `serial_parameters` - Definitions for how the serial devices should be configured.
    /// * `serial_jail` - Jail used for serial devices created here.
    /// * `battery` - Defines what battery device will be created.
    /// * `vm` - A VM implementation to build upon.
    /// * `ramoops_region` - Region allocated for ramoops.
    /// * `devices` - The devices to be built into the VM.
    /// * `irq_chip` - The IRQ chip implemention for the VM.
    fn build_vm<V, Vcpu>(
        components: VmComponents,
        exit_evt: &Event,
        reset_evt: &Event,
        system_allocator: &mut SystemAllocator,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        battery: (&Option<BatteryType>, Option<Minijail>),
        vm: V,
        ramoops_region: Option<pstore::RamoopsRegion>,
        devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
        irq_chip: &mut dyn IrqChipArch,
        kvm_vcpu_ids: &mut Vec<usize>,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmArch,
        Vcpu: VcpuArch;

    /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine object.
    /// * `hypervisor` - The `Hypervisor` that created the vcpu.
    /// * `irq_chip` - The `IrqChip` associated with this vm.
    /// * `vcpu` - The VCPU object to configure.
    /// * `vcpu_id` - The id of the given `vcpu`.
    /// * `num_cpus` - Number of virtual CPUs the guest will have.
    /// * `has_bios` - Whether the `VmImage` is a `Bios` image
    fn configure_vcpu<V: Vm>(
        vm: &V,
        hypervisor: &dyn HypervisorArch,
        irq_chip: &mut dyn IrqChipArch,
        vcpu: &mut dyn VcpuArch,
        vcpu_id: usize,
        num_cpus: usize,
        has_bios: bool,
        no_smt: bool,
        host_cpu_topology: bool,
    ) -> Result<(), Self::Error>;

    /// Configures and add a pci device into vm
    fn register_pci_device<V: VmArch, Vcpu: VcpuArch>(
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        device: Box<dyn PciDevice>,
        minijail: Option<Minijail>,
        resources: &mut SystemAllocator,
    ) -> Result<PciAddress, Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Reads vCPU's registers.
    fn debug_read_registers<T: VcpuArch>(vcpu: &T) -> Result<GdbStubRegs, Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Writes vCPU's registers.
    fn debug_write_registers<T: VcpuArch>(vcpu: &T, regs: &GdbStubRegs) -> Result<(), Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Reads bytes from the guest memory.
    fn debug_read_memory<T: VcpuArch>(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Writes bytes to the specified guest memory.
    fn debug_write_memory<T: VcpuArch>(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        buf: &[u8],
    ) -> Result<(), Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Make the next vCPU's run single-step.
    fn debug_enable_singlestep<T: VcpuArch>(vcpu: &T) -> Result<(), Self::Error>;

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    /// Set hardware breakpoints at the given addresses.
    fn debug_set_hw_breakpoints<T: VcpuArch>(
        vcpu: &T,
        breakpoints: &[GuestAddress],
    ) -> Result<(), Self::Error>;
}

/// Errors for device manager.
#[sorted]
#[derive(Error, Debug)]
pub enum DeviceRegistrationError {
    /// No more MMIO space available.
    #[error("no more addresses are available")]
    AddrsExhausted,
    /// Could not allocate device address space for the device.
    #[error("Allocating device addresses: {0}")]
    AllocateDeviceAddrs(PciDeviceError),
    /// Could not allocate IO space for the device.
    #[error("Allocating IO addresses: {0}")]
    AllocateIoAddrs(PciDeviceError),
    /// Could not allocate MMIO or IO resource for the device.
    #[error("Allocating IO resource: {0}")]
    AllocateIoResource(resources::Error),
    /// Could not allocate an IRQ number.
    #[error("Allocating IRQ number")]
    AllocateIrq,
    /// Could not allocate IRQ resource for the device.
    #[error("Allocating IRQ resource: {0}")]
    AllocateIrqResource(devices::vfio::VfioError),
    /// Unable to clone a jail for the device.
    #[error("failed to clone jail: {0}")]
    CloneJail(minijail::Error),
    /// Appending to kernel command line failed.
    #[error("unable to add device to kernel command line: {0}")]
    Cmdline(kernel_cmdline::Error),
    /// Configure window size failed.
    #[error("failed to configure window size: {0}")]
    ConfigureWindowSize(PciDeviceError),
    // Unable to create a pipe.
    #[error("failed to create pipe: {0}")]
    CreatePipe(base::Error),
    // Unable to create serial device from serial parameters
    #[error("failed to create serial device: {0}")]
    CreateSerialDevice(devices::SerialError),
    // Unable to create tube
    #[error("failed to create tube: {0}")]
    CreateTube(base::TubeError),
    /// Could not clone an event.
    #[error("failed to clone event: {0}")]
    EventClone(base::Error),
    /// Could not create an event.
    #[error("failed to create event: {0}")]
    EventCreate(base::Error),
    /// No more IRQs are available.
    #[error("no more IRQs are available")]
    IrqsExhausted,
    /// Missing a required serial device.
    #[error("missing required serial device {0}")]
    MissingRequiredSerialDevice(u8),
    /// Could not add a device to the mmio bus.
    #[error("failed to add to mmio bus: {0}")]
    MmioInsert(BusError),
    /// Failed to initialize proxy device for jailed device.
    #[error("failed to create proxy device: {0}")]
    ProxyDeviceCreation(devices::ProxyError),
    /// Failed to register battery device.
    #[error("failed to register battery device to VM: {0}")]
    RegisterBattery(devices::BatteryError),
    /// Could not register PCI device capabilities.
    #[error("could not register PCI device capabilities: {0}")]
    RegisterDeviceCapabilities(PciDeviceError),
    /// Failed to register ioevent with VM.
    #[error("failed to register ioevent to VM: {0}")]
    RegisterIoevent(base::Error),
    /// Failed to register irq event with VM.
    #[error("failed to register irq event to VM: {0}")]
    RegisterIrqfd(base::Error),
    /// Could not setup VFIO platform IRQ for the device.
    #[error("Setting up VFIO platform IRQ: {0}")]
    SetupVfioPlatformIrq(anyhow::Error),
}

/// Config a PCI device for used by this vm.
pub fn configure_pci_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    mut device: Box<dyn PciDevice>,
    jail: Option<Minijail>,
    resources: &mut SystemAllocator,
) -> Result<PciAddress, DeviceRegistrationError> {
    // Allocate PCI device address before allocating BARs.
    let pci_address = device
        .allocate_address(resources)
        .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;

    // Allocate ranges that may need to be in the low MMIO region (MmioType::Low).
    let mmio_ranges = device
        .allocate_io_bars(resources)
        .map_err(DeviceRegistrationError::AllocateIoAddrs)?;

    // Allocate device ranges that may be in low or high MMIO after low-only ranges.
    let device_ranges = device
        .allocate_device_bars(resources)
        .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;

    // Do not suggest INTx for hot-plug devices.
    let intx_event = devices::IrqLevelEvent::new().map_err(DeviceRegistrationError::EventCreate)?;

    if let Some((gsi, _pin)) = device.assign_irq(&intx_event, None) {
        resources.reserve_irq(gsi);

        linux
            .irq_chip
            .as_irq_chip_mut()
            .register_level_irq_event(gsi, &intx_event)
            .map_err(DeviceRegistrationError::RegisterIrqfd)?;
    }

    let mut keep_rds = device.keep_rds();
    syslog::push_descriptors(&mut keep_rds);

    device
        .register_device_capabilities()
        .map_err(DeviceRegistrationError::RegisterDeviceCapabilities)?;
    for (event, addr, datamatch) in device.ioevents() {
        let io_addr = IoEventAddress::Mmio(addr);
        linux
            .vm
            .register_ioevent(event, io_addr, datamatch)
            .map_err(DeviceRegistrationError::RegisterIoevent)?;
        keep_rds.push(event.as_raw_descriptor());
    }
    let arced_dev: Arc<Mutex<dyn BusDevice>> = if let Some(jail) = jail {
        let proxy = ProxyDevice::new(device, &jail, keep_rds)
            .map_err(DeviceRegistrationError::ProxyDeviceCreation)?;
        linux
            .pid_debug_label_map
            .insert(proxy.pid() as u32, proxy.debug_label());
        Arc::new(Mutex::new(proxy))
    } else {
        device.on_sandboxed();
        Arc::new(Mutex::new(device))
    };

    linux
        .root_config
        .lock()
        .add_device(pci_address, arced_dev.clone());

    for range in &mmio_ranges {
        linux
            .mmio_bus
            .insert(arced_dev.clone(), range.addr, range.size)
            .map_err(DeviceRegistrationError::MmioInsert)?;
    }

    for range in &device_ranges {
        linux
            .mmio_bus
            .insert(arced_dev.clone(), range.addr, range.size)
            .map_err(DeviceRegistrationError::MmioInsert)?;
    }

    Ok(pci_address)
}

/// Creates a platform device for use by this Vm.
pub fn generate_platform_bus(
    devices: Vec<(VfioPlatformDevice, Option<Minijail>)>,
    irq_chip: &mut dyn IrqChip,
    mmio_bus: &Bus,
    resources: &mut SystemAllocator,
) -> Result<BTreeMap<u32, String>, DeviceRegistrationError> {
    let mut pid_labels = BTreeMap::new();

    // Allocate ranges that may need to be in the Platform MMIO region (MmioType::Platform).
    for (mut device, jail) in devices.into_iter() {
        let ranges = device
            .allocate_regions(resources)
            .map_err(DeviceRegistrationError::AllocateIoResource)?;

        let mut keep_rds = device.keep_rds();
        syslog::push_descriptors(&mut keep_rds);

        let irqs = device
            .get_platform_irqs()
            .map_err(DeviceRegistrationError::AllocateIrqResource)?;
        for irq in irqs.into_iter() {
            let irq_num = resources
                .allocate_irq()
                .ok_or(DeviceRegistrationError::AllocateIrq)?;

            if device.irq_is_automask(&irq) {
                let irq_evt =
                    devices::IrqLevelEvent::new().map_err(DeviceRegistrationError::EventCreate)?;
                irq_chip
                    .register_level_irq_event(irq_num, &irq_evt)
                    .map_err(DeviceRegistrationError::RegisterIrqfd)?;
                device
                    .assign_level_platform_irq(&irq_evt, irq.index)
                    .map_err(DeviceRegistrationError::SetupVfioPlatformIrq)?;
                keep_rds.extend(irq_evt.as_raw_descriptors());
            } else {
                let irq_evt =
                    devices::IrqEdgeEvent::new().map_err(DeviceRegistrationError::EventCreate)?;
                irq_chip
                    .register_edge_irq_event(irq_num, &irq_evt)
                    .map_err(DeviceRegistrationError::RegisterIrqfd)?;
                device
                    .assign_edge_platform_irq(&irq_evt, irq.index)
                    .map_err(DeviceRegistrationError::SetupVfioPlatformIrq)?;
                keep_rds.extend(irq_evt.as_raw_descriptors());
            }
        }

        let arced_dev: Arc<Mutex<dyn BusDevice>> = if let Some(jail) = jail {
            let proxy = ProxyDevice::new(device, &jail, keep_rds)
                .map_err(DeviceRegistrationError::ProxyDeviceCreation)?;
            pid_labels.insert(proxy.pid() as u32, proxy.debug_label());
            Arc::new(Mutex::new(proxy))
        } else {
            device.on_sandboxed();
            Arc::new(Mutex::new(device))
        };
        for range in &ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }
    Ok(pid_labels)
}

/// Creates a root PCI device for use by this Vm.
pub fn generate_pci_root(
    mut devices: Vec<(Box<dyn PciDevice>, Option<Minijail>)>,
    irq_chip: &mut dyn IrqChip,
    mmio_bus: Arc<Bus>,
    io_bus: Arc<Bus>,
    resources: &mut SystemAllocator,
    vm: &mut impl Vm,
    max_irqs: usize,
) -> Result<
    (
        PciRoot,
        Vec<(PciAddress, u32, PciInterruptPin)>,
        BTreeMap<u32, String>,
    ),
    DeviceRegistrationError,
> {
    let mut root = PciRoot::new(Arc::downgrade(&mmio_bus), Arc::downgrade(&io_bus));
    let mut pid_labels = BTreeMap::new();
    // The map of (dev_idx, bus), find bus number through dev_idx in devices
    let mut devid_buses: BTreeMap<usize, u8> = BTreeMap::new();
    // The map of (bridge secondary bus number, Vec<sub device BarRange>)
    let mut bridge_bar_ranges: BTreeMap<u8, Vec<BarRange>> = BTreeMap::new();

    // Allocate PCI device address before allocating BARs.
    let mut device_addrs = Vec::<PciAddress>::new();
    for (dev_idx, (device, _jail)) in devices.iter_mut().enumerate() {
        let address = device
            .allocate_address(resources)
            .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;
        device_addrs.push(address);

        if address.bus > 0 {
            devid_buses.insert(dev_idx, address.bus);
        }

        if PciBridge::is_pci_bridge(device) {
            let sec_bus = PciBridge::get_secondary_bus_num(device);
            bridge_bar_ranges.insert(sec_bus, Vec::<BarRange>::new());
        }
    }

    // Allocate ranges that may need to be in the low MMIO region (MmioType::Low).
    let mut io_ranges = BTreeMap::new();
    for (dev_idx, (device, _jail)) in devices.iter_mut().enumerate() {
        let mut ranges = device
            .allocate_io_bars(resources)
            .map_err(DeviceRegistrationError::AllocateIoAddrs)?;
        io_ranges.insert(dev_idx, ranges.clone());

        if let Some(bus) = devid_buses.get(&dev_idx) {
            if let Some(bridge_bar) = bridge_bar_ranges.get_mut(bus) {
                bridge_bar.append(&mut ranges);
            }
        }
    }

    // Allocate device ranges that may be in low or high MMIO after low-only ranges.
    let mut device_ranges = BTreeMap::new();
    for (dev_idx, (device, _jail)) in devices.iter_mut().enumerate() {
        let mut ranges = device
            .allocate_device_bars(resources)
            .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;
        device_ranges.insert(dev_idx, ranges.clone());

        if let Some(bus) = devid_buses.get(&dev_idx) {
            if let Some(bridge_bar) = bridge_bar_ranges.get_mut(bus) {
                bridge_bar.append(&mut ranges);
            }
        }
    }

    for (device, _jail) in devices.iter_mut() {
        if PciBridge::is_pci_bridge(device) {
            let sec_bus = PciBridge::get_secondary_bus_num(device);
            if let Some(bridge_bar) = bridge_bar_ranges.get(&sec_bus) {
                device
                    .configure_bridge_window(resources, bridge_bar)
                    .map_err(DeviceRegistrationError::ConfigureWindowSize)?;
            }
        }
    }

    // Allocate legacy INTx
    let mut pci_irqs = Vec::new();
    let mut irqs: Vec<Option<u32>> = vec![None; max_irqs];

    for (dev_idx, (device, _jail)) in devices.iter_mut().enumerate() {
        // For default interrupt routing use next preallocated interrupt from the pool.
        let irq_num = if let Some(irq) = irqs[dev_idx % max_irqs] {
            irq
        } else {
            let irq = resources
                .allocate_irq()
                .ok_or(DeviceRegistrationError::AllocateIrq)?;
            irqs[dev_idx % max_irqs] = Some(irq);
            irq
        };

        let intx_event =
            devices::IrqLevelEvent::new().map_err(DeviceRegistrationError::EventCreate)?;

        if let Some((gsi, pin)) = device.assign_irq(&intx_event, Some(irq_num)) {
            // reserve INTx if needed and non-default.
            if gsi != irq_num {
                resources.reserve_irq(gsi);
            };
            irq_chip
                .register_level_irq_event(gsi, &intx_event)
                .map_err(DeviceRegistrationError::RegisterIrqfd)?;

            pci_irqs.push((device_addrs[dev_idx], gsi, pin));
        }
    }

    for (dev_idx, (mut device, jail)) in devices.into_iter().enumerate() {
        let address = device_addrs[dev_idx];

        let mut keep_rds = device.keep_rds();
        syslog::push_descriptors(&mut keep_rds);
        keep_rds.append(&mut vm.get_memory().as_raw_descriptors());

        let ranges = io_ranges.remove(&dev_idx).unwrap_or_default();
        let device_ranges = device_ranges.remove(&dev_idx).unwrap_or_default();
        device
            .register_device_capabilities()
            .map_err(DeviceRegistrationError::RegisterDeviceCapabilities)?;
        for (event, addr, datamatch) in device.ioevents() {
            let io_addr = IoEventAddress::Mmio(addr);
            vm.register_ioevent(event, io_addr, datamatch)
                .map_err(DeviceRegistrationError::RegisterIoevent)?;
            keep_rds.push(event.as_raw_descriptor());
        }

        let arced_dev: Arc<Mutex<dyn BusDevice>> = if let Some(jail) = jail {
            let proxy = ProxyDevice::new(device, &jail, keep_rds)
                .map_err(DeviceRegistrationError::ProxyDeviceCreation)?;
            pid_labels.insert(proxy.pid() as u32, proxy.debug_label());
            Arc::new(Mutex::new(proxy))
        } else {
            device.on_sandboxed();
            Arc::new(Mutex::new(device))
        };
        root.add_device(address, arced_dev.clone());
        for range in &ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.addr, range.size)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }

        for range in &device_ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.addr, range.size)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }
    Ok((root, pci_irqs, pid_labels))
}

/// Adds goldfish battery
/// return the platform needed resouces include its AML data, irq number
///
/// # Arguments
///
/// * `amls` - the vector to put the goldfish battery AML
/// * `battery_jail` - used when sandbox is enabled
/// * `mmio_bus` - bus to add the devices to
/// * `irq_chip` - the IrqChip object for registering irq events
/// * `irq_num` - assigned interrupt to use
/// * `resources` - the SystemAllocator to allocate IO and MMIO for acpi
pub fn add_goldfish_battery(
    amls: &mut Vec<u8>,
    battery_jail: Option<Minijail>,
    mmio_bus: &Bus,
    irq_chip: &mut dyn IrqChip,
    irq_num: u32,
    resources: &mut SystemAllocator,
) -> Result<Tube, DeviceRegistrationError> {
    let alloc = resources.get_anon_alloc();
    let mmio_base = resources
        .mmio_allocator(MmioType::Low)
        .allocate_with_align(
            devices::bat::GOLDFISHBAT_MMIO_LEN,
            alloc,
            "GoldfishBattery".to_string(),
            devices::bat::GOLDFISHBAT_MMIO_LEN,
        )
        .map_err(DeviceRegistrationError::AllocateIoResource)?;

    let irq_evt = devices::IrqLevelEvent::new().map_err(DeviceRegistrationError::EventCreate)?;

    irq_chip
        .register_level_irq_event(irq_num, &irq_evt)
        .map_err(DeviceRegistrationError::RegisterIrqfd)?;

    let (control_tube, response_tube) =
        Tube::pair().map_err(DeviceRegistrationError::CreateTube)?;

    #[cfg(feature = "power-monitor-powerd")]
    let create_monitor = Some(Box::new(power_monitor::powerd::DBusMonitor::connect)
        as Box<dyn power_monitor::CreatePowerMonitorFn>);

    #[cfg(not(feature = "power-monitor-powerd"))]
    let create_monitor = None;

    let goldfish_bat =
        devices::GoldfishBattery::new(mmio_base, irq_num, irq_evt, response_tube, create_monitor)
            .map_err(DeviceRegistrationError::RegisterBattery)?;
    goldfish_bat.to_aml_bytes(amls);

    match battery_jail.as_ref() {
        Some(jail) => {
            let mut keep_rds = goldfish_bat.keep_rds();
            syslog::push_fds(&mut keep_rds);
            mmio_bus
                .insert(
                    Arc::new(Mutex::new(
                        ProxyDevice::new(goldfish_bat, jail, keep_rds)
                            .map_err(DeviceRegistrationError::ProxyDeviceCreation)?,
                    )),
                    mmio_base,
                    devices::bat::GOLDFISHBAT_MMIO_LEN,
                )
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
        None => {
            mmio_bus
                .insert(
                    Arc::new(Mutex::new(goldfish_bat)),
                    mmio_base,
                    devices::bat::GOLDFISHBAT_MMIO_LEN,
                )
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }

    Ok(control_tube)
}

/// Errors for image loading.
#[sorted]
#[derive(Error, Debug)]
pub enum LoadImageError {
    #[error("Alignment not a power of two: {0}")]
    BadAlignment(u64),
    #[error("Image size too large: {0}")]
    ImageSizeTooLarge(u64),
    #[error("Reading image into memory failed: {0}")]
    ReadToMemory(GuestMemoryError),
    #[error("Seek failed: {0}")]
    Seek(io::Error),
}

/// Load an image from a file into guest memory.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `guest_addr` - The starting address to load the image in the guest memory.
/// * `max_size` - The amount of space in bytes available in the guest memory for the image.
/// * `image` - The file containing the image to be loaded.
///
/// The size in bytes of the loaded image is returned.
pub fn load_image<F>(
    guest_mem: &GuestMemory,
    image: &mut F,
    guest_addr: GuestAddress,
    max_size: u64,
) -> Result<usize, LoadImageError>
where
    F: Read + Seek + AsRawDescriptor,
{
    let size = image.seek(SeekFrom::End(0)).map_err(LoadImageError::Seek)?;

    if size > usize::max_value() as u64 || size > max_size {
        return Err(LoadImageError::ImageSizeTooLarge(size));
    }

    // This is safe due to the bounds check above.
    let size = size as usize;

    image
        .seek(SeekFrom::Start(0))
        .map_err(LoadImageError::Seek)?;

    guest_mem
        .read_to_memory(guest_addr, image, size)
        .map_err(LoadImageError::ReadToMemory)?;

    Ok(size)
}

/// Load an image from a file into guest memory at the highest possible address.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `image` - The file containing the image to be loaded.
/// * `min_guest_addr` - The minimum address of the start of the image.
/// * `max_guest_addr` - The address to load the last byte of the image.
/// * `align` - The minimum alignment of the start address of the image in bytes
///   (must be a power of two).
///
/// The guest address and size in bytes of the loaded image are returned.
pub fn load_image_high<F>(
    guest_mem: &GuestMemory,
    image: &mut F,
    min_guest_addr: GuestAddress,
    max_guest_addr: GuestAddress,
    align: u64,
) -> Result<(GuestAddress, usize), LoadImageError>
where
    F: Read + Seek + AsRawDescriptor,
{
    if !align.is_power_of_two() {
        return Err(LoadImageError::BadAlignment(align));
    }

    let max_size = max_guest_addr.offset_from(min_guest_addr) & !(align - 1);
    let size = image.seek(SeekFrom::End(0)).map_err(LoadImageError::Seek)?;

    if size > usize::max_value() as u64 || size > max_size {
        return Err(LoadImageError::ImageSizeTooLarge(size));
    }

    image
        .seek(SeekFrom::Start(0))
        .map_err(LoadImageError::Seek)?;

    // Load image at the maximum aligned address allowed.
    // The subtraction cannot underflow because of the size checks above.
    let guest_addr = GuestAddress((max_guest_addr.offset() - size) & !(align - 1));

    // This is safe due to the bounds check above.
    let size = size as usize;

    guest_mem
        .read_to_memory(guest_addr, image, size)
        .map_err(LoadImageError::ReadToMemory)?;

    Ok((guest_addr, size))
}
