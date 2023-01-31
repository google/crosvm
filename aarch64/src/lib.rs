// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ARM 64-bit architecture support.

#![cfg(any(target_arch = "arm", target_arch = "aarch64"))]

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use arch::get_serial_cmdline;
use arch::CpuSet;
use arch::DtbOverlay;
use arch::GetSerialCmdlineError;
use arch::RunnableLinuxVm;
use arch::VcpuAffinity;
use arch::VmComponents;
use arch::VmImage;
use base::Event;
use base::MemoryMappingBuilder;
use base::SendTube;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::vmwdt::VMWDT_DEFAULT_CLOCK_HZ;
use devices::vmwdt::VMWDT_DEFAULT_TIMEOUT_SEC;
use devices::Bus;
use devices::BusDeviceObj;
use devices::BusError;
use devices::BusType;
use devices::IrqChip;
use devices::IrqChipAArch64;
use devices::IrqEventSource;
use devices::PciAddress;
use devices::PciConfigMmio;
use devices::PciDevice;
use devices::PciRootCommand;
use devices::Serial;
#[cfg(any(target_os = "android", target_os = "linux"))]
use devices::VirtCpufreq;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
use hypervisor::CpuConfigAArch64;
use hypervisor::DeviceKind;
use hypervisor::Hypervisor;
use hypervisor::HypervisorCap;
use hypervisor::ProtectionType;
use hypervisor::VcpuAArch64;
use hypervisor::VcpuFeature;
use hypervisor::VcpuInitAArch64;
use hypervisor::VcpuRegAArch64;
use hypervisor::Vm;
use hypervisor::VmAArch64;
#[cfg(windows)]
use jail::FakeMinijailStub as Minijail;
use kernel_loader::LoadedKernel;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use remain::sorted;
use resources::AddressRange;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
#[cfg(any(target_os = "android", target_os = "linux"))]
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_control::BatControl;
use vm_control::BatteryType;
use vm_memory::GuestAddress;
#[cfg(feature = "gdb")]
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use vm_memory::MemoryRegionOptions;
use vm_memory::MemoryRegionPurpose;

mod fdt;

// We place the kernel at the very beginning of physical memory.
const AARCH64_KERNEL_OFFSET: u64 = 0;
const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;
const AARCH64_INITRD_ALIGN: u64 = 0x1000000;

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// This indicates the start of DRAM inside the physical address space.
const AARCH64_PHYS_MEM_START: u64 = 0x80000000;
const AARCH64_AXI_BASE: u64 = 0x40000000;
const AARCH64_PLATFORM_MMIO_SIZE: u64 = 0x800000;

// FDT is placed at the front of RAM when booting in BIOS mode.
const AARCH64_FDT_OFFSET_IN_BIOS_MODE: u64 = 0x0;
// Therefore, the BIOS is placed after the FDT in memory.
const AARCH64_BIOS_OFFSET: u64 = AARCH64_FDT_MAX_SIZE;
const AARCH64_BIOS_MAX_LEN: u64 = 1 << 20;

const AARCH64_PROTECTED_VM_FW_MAX_SIZE: u64 = 0x400000;
const AARCH64_PROTECTED_VM_FW_START: u64 =
    AARCH64_PHYS_MEM_START - AARCH64_PROTECTED_VM_FW_MAX_SIZE;

const AARCH64_PVTIME_IPA_MAX_SIZE: u64 = 0x10000;
const AARCH64_PVTIME_IPA_START: u64 = AARCH64_MMIO_BASE - AARCH64_PVTIME_IPA_MAX_SIZE;
const AARCH64_PVTIME_SIZE: u64 = 64;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;

// PSR (Processor State Register) bits
const PSR_MODE_EL1H: u64 = 0x00000005;
const PSR_F_BIT: u64 = 0x00000040;
const PSR_I_BIT: u64 = 0x00000080;
const PSR_A_BIT: u64 = 0x00000100;
const PSR_D_BIT: u64 = 0x00000200;

enum PayloadType {
    Bios {
        entry: GuestAddress,
        image_size: u64,
    },
    Kernel(LoadedKernel),
}

impl PayloadType {
    fn entry(&self) -> GuestAddress {
        match self {
            Self::Bios {
                entry,
                image_size: _,
            } => *entry,
            Self::Kernel(k) => k.entry,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Bios {
                entry: _,
                image_size,
            } => *image_size,
            Self::Kernel(k) => k.size,
        }
    }
}

fn get_kernel_addr() -> GuestAddress {
    GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_KERNEL_OFFSET)
}

fn get_bios_addr() -> GuestAddress {
    GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_BIOS_OFFSET)
}

// When static swiotlb allocation is required, returns the address it should be allocated at.
// Otherwise, returns None.
fn get_swiotlb_addr(
    memory_size: u64,
    hypervisor: &(impl Hypervisor + ?Sized),
) -> Option<GuestAddress> {
    if hypervisor.check_capability(HypervisorCap::StaticSwiotlbAllocationRequired) {
        Some(GuestAddress(AARCH64_PHYS_MEM_START + memory_size))
    } else {
        None
    }
}

// Serial device requires 8 bytes of registers;
const AARCH64_SERIAL_SIZE: u64 = 0x8;
// This was the speed kvmtool used, not sure if it matters.
const AARCH64_SERIAL_SPEED: u32 = 1843200;
// The serial device gets the first interrupt line
// Which gets mapped to the first SPI interrupt (physical 32).
const AARCH64_SERIAL_1_3_IRQ: u32 = 0;
const AARCH64_SERIAL_2_4_IRQ: u32 = 2;

// Place the RTC device at page 2
const AARCH64_RTC_ADDR: u64 = 0x2000;
// The RTC device gets one 4k page
const AARCH64_RTC_SIZE: u64 = 0x1000;
// The RTC device gets the second interrupt line
const AARCH64_RTC_IRQ: u32 = 1;

// The Goldfish battery device gets the 3rd interrupt line
const AARCH64_BAT_IRQ: u32 = 3;

// Place the virtual watchdog device at page 3
const AARCH64_VMWDT_ADDR: u64 = 0x3000;
// The virtual watchdog device gets one 4k page
const AARCH64_VMWDT_SIZE: u64 = 0x1000;

// PCI MMIO configuration region base address.
const AARCH64_PCI_CFG_BASE: u64 = 0x10000;
// PCI MMIO configuration region size.
const AARCH64_PCI_CFG_SIZE: u64 = 0x1000000;
// This is the base address of MMIO devices.
const AARCH64_MMIO_BASE: u64 = 0x2000000;
// Size of the whole MMIO region.
const AARCH64_MMIO_SIZE: u64 = 0x2000000;
// Virtio devices start at SPI interrupt number 4
const AARCH64_IRQ_BASE: u32 = 4;

// Virtual CPU Frequency Device.
const AARCH64_VIRTFREQ_BASE: u64 = 0x1040000;
const AARCH64_VIRTFREQ_SIZE: u64 = 0x8;
const AARCH64_VIRTFREQ_MAXSIZE: u64 = 0x10000;

// PMU PPI interrupt, same as qemu
const AARCH64_PMU_IRQ: u32 = 7;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to allocate IRQ number")]
    AllocateIrq,
    #[error("bios could not be loaded: {0}")]
    BiosLoadFailure(arch::LoadImageError),
    #[error("failed to build arm pvtime memory: {0}")]
    BuildPvtimeError(base::MmapError),
    #[error("unable to clone an Event: {0}")]
    CloneEvent(base::Error),
    #[error("failed to clone IRQ chip: {0}")]
    CloneIrqChip(base::Error),
    #[error("the given kernel command line was invalid: {0}")]
    Cmdline(kernel_cmdline::Error),
    #[error("failed to configure CPU Frequencies: {0}")]
    CpuFrequencies(base::Error),
    #[error("failed to configure CPU topology: {0}")]
    CpuTopology(base::Error),
    #[error("unable to create battery devices: {0}")]
    CreateBatDevices(arch::DeviceRegistrationError),
    #[error("unable to make an Event: {0}")]
    CreateEvent(base::Error),
    #[error("FDT could not be created: {0}")]
    CreateFdt(cros_fdt::Error),
    #[error("failed to create GIC: {0}")]
    CreateGICFailure(base::Error),
    #[error("failed to create a PCI root hub: {0}")]
    CreatePciRoot(arch::DeviceRegistrationError),
    #[error("failed to create platform bus: {0}")]
    CreatePlatformBus(arch::DeviceRegistrationError),
    #[error("unable to create serial devices: {0}")]
    CreateSerialDevices(arch::DeviceRegistrationError),
    #[error("failed to create socket: {0}")]
    CreateSocket(io::Error),
    #[error("failed to create VCPU: {0}")]
    CreateVcpu(base::Error),
    #[error("custom pVM firmware could not be loaded: {0}")]
    CustomPvmFwLoadFailure(arch::LoadImageError),
    #[error("vm created wrong kind of vcpu")]
    DowncastVcpu,
    #[error("failed to enable singlestep execution: {0}")]
    EnableSinglestep(base::Error),
    #[error("failed to finalize IRQ chip: {0}")]
    FinalizeIrqChip(base::Error),
    #[error("failed to get HW breakpoint count: {0}")]
    GetMaxHwBreakPoint(base::Error),
    #[error("failed to get PSCI version: {0}")]
    GetPsciVersion(base::Error),
    #[error("failed to get serial cmdline: {0}")]
    GetSerialCmdline(GetSerialCmdlineError),
    #[error("failed to initialize arm pvtime: {0}")]
    InitPvtimeError(base::Error),
    #[error("initrd could not be loaded: {0}")]
    InitrdLoadFailure(arch::LoadImageError),
    #[error("failed to initialize virtual machine {0}")]
    InitVmError(base::Error),
    #[error("kernel could not be loaded: {0}")]
    KernelLoadFailure(kernel_loader::Error),
    #[error("error loading Kernel from Elf image: {0}")]
    LoadElfKernel(kernel_loader::Error),
    #[error("failed to map arm pvtime memory: {0}")]
    MapPvtimeError(base::Error),
    #[error("pVM firmware could not be loaded: {0}")]
    PvmFwLoadFailure(base::Error),
    #[error("ramoops address is different from high_mmio_base: {0} vs {1}")]
    RamoopsAddress(u64, u64),
    #[error("error reading guest memory: {0}")]
    ReadGuestMemory(vm_memory::GuestMemoryError),
    #[error("error reading CPU register: {0}")]
    ReadReg(base::Error),
    #[error("error reading CPU registers: {0}")]
    ReadRegs(base::Error),
    #[error("failed to register irq fd: {0}")]
    RegisterIrqfd(base::Error),
    #[error("error registering PCI bus: {0}")]
    RegisterPci(BusError),
    #[error("error registering virtual cpufreq device: {0}")]
    RegisterVirtCpufreq(BusError),
    #[error("error registering virtual socket device: {0}")]
    RegisterVsock(arch::DeviceRegistrationError),
    #[error("failed to set device attr: {0}")]
    SetDeviceAttr(base::Error),
    #[error("failed to set a hardware breakpoint: {0}")]
    SetHwBreakpoint(base::Error),
    #[error("failed to set register: {0}")]
    SetReg(base::Error),
    #[error("failed to set up guest memory: {0}")]
    SetupGuestMemory(GuestMemoryError),
    #[error("this function isn't supported")]
    Unsupported,
    #[error("failed to initialize VCPU: {0}")]
    VcpuInit(base::Error),
    #[error("error writing guest memory: {0}")]
    WriteGuestMemory(GuestMemoryError),
    #[error("error writing CPU register: {0}")]
    WriteReg(base::Error),
    #[error("error writing CPU registers: {0}")]
    WriteRegs(base::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Returns the address in guest memory at which the FDT should be located.
fn fdt_address(memory_end: GuestAddress, has_bios: bool) -> GuestAddress {
    // TODO(rammuthiah) make kernel and BIOS startup use FDT from the same location. ARCVM startup
    // currently expects the kernel at 0x80080000 and the FDT at the end of RAM for unknown reasons.
    // Root cause and figure out how to fold these code paths together.
    if has_bios {
        GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_FDT_OFFSET_IN_BIOS_MODE)
    } else {
        // Put fdt up near the top of memory
        // TODO(sonnyrao): will have to handle this differently if there's
        // > 4GB memory
        memory_end
            .checked_sub(AARCH64_FDT_MAX_SIZE)
            .expect("Not enough memory for FDT")
            .checked_sub(0x10000)
            .expect("Not enough memory for FDT")
    }
}

pub struct AArch64;

impl arch::LinuxArch for AArch64 {
    type Error = Error;

    /// Returns a Vec of the valid memory addresses.
    /// These should be used to configure the GuestMemory structure for the platform.
    fn guest_memory_layout(
        components: &VmComponents,
        hypervisor: &impl Hypervisor,
    ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
        let mut memory_regions = vec![(
            GuestAddress(AARCH64_PHYS_MEM_START),
            components.memory_size,
            Default::default(),
        )];

        // Allocate memory for the pVM firmware.
        if components.hv_cfg.protection_type.runs_firmware() {
            memory_regions.push((
                GuestAddress(AARCH64_PROTECTED_VM_FW_START),
                AARCH64_PROTECTED_VM_FW_MAX_SIZE,
                MemoryRegionOptions::new().purpose(MemoryRegionPurpose::ProtectedFirmwareRegion),
            ));
        }

        if let Some(size) = components.swiotlb {
            if let Some(addr) = get_swiotlb_addr(components.memory_size, hypervisor) {
                memory_regions.push((
                    addr,
                    size,
                    MemoryRegionOptions::new().purpose(MemoryRegionPurpose::StaticSwiotlbRegion),
                ));
            }
        }

        Ok(memory_regions)
    }

    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
        Self::get_resource_allocator_config(
            vm.get_memory().end_addr(),
            vm.get_guest_phys_addr_bits(),
        )
    }

    fn build_vm<V, Vcpu>(
        mut components: VmComponents,
        _vm_evt_wrtube: &SendTube,
        system_allocator: &mut SystemAllocator,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        (bat_type, bat_jail): (Option<BatteryType>, Option<Minijail>),
        mut vm: V,
        ramoops_region: Option<arch::pstore::RamoopsRegion>,
        devs: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
        irq_chip: &mut dyn IrqChipAArch64,
        vcpu_ids: &mut Vec<usize>,
        dump_device_tree_blob: Option<PathBuf>,
        _debugcon_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        #[cfg(any(target_os = "android", target_os = "linux"))] _guest_suspended_cvar: Option<
            Arc<(Mutex<bool>, Condvar)>,
        >,
        device_tree_overlays: Vec<DtbOverlay>,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmAArch64,
        Vcpu: VcpuAArch64,
    {
        let has_bios = matches!(components.vm_image, VmImage::Bios(_));
        let mem = vm.get_memory().clone();

        // separate out image loading from other setup to get a specific error for
        // image loading
        let mut initrd = None;
        let payload = match components.vm_image {
            VmImage::Bios(ref mut bios) => {
                let image_size =
                    arch::load_image(&mem, bios, get_bios_addr(), AARCH64_BIOS_MAX_LEN)
                        .map_err(Error::BiosLoadFailure)?;
                PayloadType::Bios {
                    entry: get_bios_addr(),
                    image_size: image_size as u64,
                }
            }
            VmImage::Kernel(ref mut kernel_image) => {
                let loaded_kernel = if let Ok(elf_kernel) = kernel_loader::load_elf(
                    &mem,
                    get_kernel_addr(),
                    kernel_image,
                    AARCH64_PHYS_MEM_START,
                ) {
                    elf_kernel
                } else {
                    kernel_loader::load_arm64_kernel(&mem, get_kernel_addr(), kernel_image)
                        .map_err(Error::KernelLoadFailure)?
                };
                let kernel_end = loaded_kernel.address_range.end;
                initrd = match components.initrd_image {
                    Some(initrd_file) => {
                        let mut initrd_file = initrd_file;
                        let initrd_addr =
                            (kernel_end + (AARCH64_INITRD_ALIGN - 1)) & !(AARCH64_INITRD_ALIGN - 1);
                        let initrd_max_size =
                            components.memory_size - (initrd_addr - AARCH64_PHYS_MEM_START);
                        let initrd_addr = GuestAddress(initrd_addr);
                        let initrd_size =
                            arch::load_image(&mem, &mut initrd_file, initrd_addr, initrd_max_size)
                                .map_err(Error::InitrdLoadFailure)?;
                        Some((initrd_addr, initrd_size))
                    }
                    None => None,
                };
                PayloadType::Kernel(loaded_kernel)
            }
        };

        let memory_end = GuestAddress(AARCH64_PHYS_MEM_START + components.memory_size);
        let fdt_offset = fdt_address(memory_end, has_bios);

        let mut use_pmu = vm
            .get_hypervisor()
            .check_capability(HypervisorCap::ArmPmuV3);
        let vcpu_count = components.vcpu_count;
        let mut has_pvtime = true;
        let mut vcpus = Vec::with_capacity(vcpu_count);
        let mut vcpu_init = Vec::with_capacity(vcpu_count);
        for vcpu_id in 0..vcpu_count {
            let vcpu: Vcpu = *vm
                .create_vcpu(vcpu_id)
                .map_err(Error::CreateVcpu)?
                .downcast::<Vcpu>()
                .map_err(|_| Error::DowncastVcpu)?;
            let per_vcpu_init = if vm
                .get_hypervisor()
                .check_capability(HypervisorCap::HypervisorInitializedBootContext)
            {
                // No registers are initialized: VcpuInitAArch64.regs is an empty BTreeMap
                Default::default()
            } else {
                Self::vcpu_init(
                    vcpu_id,
                    &payload,
                    fdt_offset,
                    components.hv_cfg.protection_type,
                )
            };
            has_pvtime &= vcpu.has_pvtime_support();
            vcpus.push(vcpu);
            vcpu_ids.push(vcpu_id);
            vcpu_init.push(per_vcpu_init);
        }

        // Initialize Vcpus after all Vcpu objects have been created.
        for (vcpu_id, vcpu) in vcpus.iter().enumerate() {
            vcpu.init(&Self::vcpu_features(vcpu_id, use_pmu))
                .map_err(Error::VcpuInit)?;
        }

        irq_chip.finalize().map_err(Error::FinalizeIrqChip)?;

        if has_pvtime {
            let pvtime_mem = MemoryMappingBuilder::new(AARCH64_PVTIME_IPA_MAX_SIZE as usize)
                .build()
                .map_err(Error::BuildPvtimeError)?;
            vm.add_memory_region(
                GuestAddress(AARCH64_PVTIME_IPA_START),
                Box::new(pvtime_mem),
                false,
                false,
            )
            .map_err(Error::MapPvtimeError)?;
        }

        if components.hv_cfg.protection_type.loads_firmware() {
            arch::load_image(
                &mem,
                &mut components
                    .pvm_fw
                    .expect("pvmfw must be available if ProtectionType loads it"),
                GuestAddress(AARCH64_PROTECTED_VM_FW_START),
                AARCH64_PROTECTED_VM_FW_MAX_SIZE,
            )
            .map_err(Error::CustomPvmFwLoadFailure)?;
        } else if components.hv_cfg.protection_type.runs_firmware() {
            // Tell the hypervisor to load the pVM firmware.
            vm.load_protected_vm_firmware(
                GuestAddress(AARCH64_PROTECTED_VM_FW_START),
                AARCH64_PROTECTED_VM_FW_MAX_SIZE,
            )
            .map_err(Error::PvmFwLoadFailure)?;
        }

        for (vcpu_id, vcpu) in vcpus.iter().enumerate() {
            use_pmu &= vcpu.init_pmu(AARCH64_PMU_IRQ as u64 + 16).is_ok();
            if has_pvtime {
                vcpu.init_pvtime(AARCH64_PVTIME_IPA_START + (vcpu_id as u64 * AARCH64_PVTIME_SIZE))
                    .map_err(Error::InitPvtimeError)?;
            }
        }

        let mmio_bus = Arc::new(devices::Bus::new(BusType::Mmio));

        // ARM doesn't really use the io bus like x86, so just create an empty bus.
        let io_bus = Arc::new(devices::Bus::new(BusType::Io));

        // Event used by PMDevice to notify crosvm that
        // guest OS is trying to suspend.
        let suspend_evt = Event::new().map_err(Error::CreateEvent)?;

        let (pci_devices, others): (Vec<_>, Vec<_>) = devs
            .into_iter()
            .partition(|(dev, _)| dev.as_pci_device().is_some());

        let pci_devices = pci_devices
            .into_iter()
            .map(|(dev, jail_orig)| (dev.into_pci_device().unwrap(), jail_orig))
            .collect();
        let (pci, pci_irqs, mut pid_debug_label_map, _amls, _gpe_scope_amls) =
            arch::generate_pci_root(
                pci_devices,
                irq_chip.as_irq_chip_mut(),
                mmio_bus.clone(),
                GuestAddress(AARCH64_PCI_CFG_BASE),
                8,
                io_bus.clone(),
                system_allocator,
                &mut vm,
                (devices::AARCH64_GIC_NR_SPIS - AARCH64_IRQ_BASE) as usize,
                None,
                #[cfg(feature = "swap")]
                swap_controller,
            )
            .map_err(Error::CreatePciRoot)?;

        let pci_root = Arc::new(Mutex::new(pci));
        let pci_bus = Arc::new(Mutex::new(PciConfigMmio::new(pci_root.clone(), 8)));
        let (platform_devices, _others): (Vec<_>, Vec<_>) = others
            .into_iter()
            .partition(|(dev, _)| dev.as_platform_device().is_some());

        let platform_devices = platform_devices
            .into_iter()
            .map(|(dev, jail_orig)| (*(dev.into_platform_device().unwrap()), jail_orig))
            .collect();
        let (platform_devices, mut platform_pid_debug_label_map, dev_resources) =
            arch::sys::linux::generate_platform_bus(
                platform_devices,
                irq_chip.as_irq_chip_mut(),
                &mmio_bus,
                system_allocator,
                &mut vm,
                #[cfg(feature = "swap")]
                swap_controller,
                components.hv_cfg.protection_type,
            )
            .map_err(Error::CreatePlatformBus)?;
        pid_debug_label_map.append(&mut platform_pid_debug_label_map);

        Self::add_arch_devs(
            irq_chip.as_irq_chip_mut(),
            &mmio_bus,
            vcpu_count,
            _vm_evt_wrtube,
        )?;

        let com_evt_1_3 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        arch::add_serial_devices(
            components.hv_cfg.protection_type,
            &mmio_bus,
            com_evt_1_3.get_trigger(),
            com_evt_2_4.get_trigger(),
            serial_parameters,
            serial_jail,
            #[cfg(feature = "swap")]
            swap_controller,
        )
        .map_err(Error::CreateSerialDevices)?;

        let source = IrqEventSource {
            device_id: Serial::device_id(),
            queue_id: 0,
            device_name: Serial::debug_label(),
        };
        irq_chip
            .register_edge_irq_event(AARCH64_SERIAL_1_3_IRQ, &com_evt_1_3, source.clone())
            .map_err(Error::RegisterIrqfd)?;
        irq_chip
            .register_edge_irq_event(AARCH64_SERIAL_2_4_IRQ, &com_evt_2_4, source)
            .map_err(Error::RegisterIrqfd)?;

        mmio_bus
            .insert(pci_bus, AARCH64_PCI_CFG_BASE, AARCH64_PCI_CFG_SIZE)
            .map_err(Error::RegisterPci)?;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        if !components.cpu_frequencies.is_empty() {
            for vcpu in 0..vcpu_count {
                let vcpu_affinity = match components.vcpu_affinity.clone() {
                    Some(VcpuAffinity::Global(v)) => v,
                    Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&vcpu).unwrap_or_default(),
                    None => panic!("vcpu_affinity needs to be set for VirtCpufreq"),
                };

                let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreq::new(
                    vcpu_affinity[0].try_into().unwrap(),
                )));

                if vcpu as u64 * AARCH64_VIRTFREQ_SIZE + AARCH64_VIRTFREQ_SIZE
                    > AARCH64_VIRTFREQ_MAXSIZE
                {
                    panic!("Exceeded maximum number of virt cpufreq devices");
                }

                mmio_bus
                    .insert(
                        virt_cpufreq,
                        AARCH64_VIRTFREQ_BASE + (vcpu as u64 * AARCH64_VIRTFREQ_SIZE),
                        AARCH64_VIRTFREQ_SIZE,
                    )
                    .map_err(Error::RegisterVirtCpufreq)?;
            }
        }

        let mut cmdline = Self::get_base_linux_cmdline();
        get_serial_cmdline(&mut cmdline, serial_parameters, "mmio")
            .map_err(Error::GetSerialCmdline)?;
        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        if let Some(ramoops_region) = ramoops_region {
            arch::pstore::add_ramoops_kernel_cmdline(&mut cmdline, &ramoops_region)
                .map_err(Error::Cmdline)?;
        }

        let psci_version = vcpus[0].get_psci_version().map_err(Error::GetPsciVersion)?;

        let pci_cfg = fdt::PciConfigRegion {
            base: AARCH64_PCI_CFG_BASE,
            size: AARCH64_PCI_CFG_SIZE,
        };

        let pci_ranges: Vec<fdt::PciRange> = system_allocator
            .mmio_pools()
            .iter()
            .map(|range| fdt::PciRange {
                space: fdt::PciAddressSpace::Memory64,
                bus_address: range.start,
                cpu_physical_address: range.start,
                size: range.len().unwrap(),
                prefetchable: false,
            })
            .collect();

        let (bat_control, bat_mmio_base_and_irq) = match bat_type {
            Some(BatteryType::Goldfish) => {
                let bat_irq = AARCH64_BAT_IRQ;

                // a dummy AML buffer. Aarch64 crosvm doesn't use ACPI.
                let mut amls = Vec::new();
                let (control_tube, mmio_base) = arch::sys::linux::add_goldfish_battery(
                    &mut amls,
                    bat_jail,
                    &mmio_bus,
                    irq_chip.as_irq_chip_mut(),
                    bat_irq,
                    system_allocator,
                    #[cfg(feature = "swap")]
                    swap_controller,
                )
                .map_err(Error::CreateBatDevices)?;
                (
                    Some(BatControl {
                        type_: BatteryType::Goldfish,
                        control_tube,
                    }),
                    Some((mmio_base, bat_irq)),
                )
            }
            None => (None, None),
        };

        let vmwdt_cfg = fdt::VmWdtConfig {
            base: AARCH64_VMWDT_ADDR,
            size: AARCH64_VMWDT_SIZE,
            clock_hz: VMWDT_DEFAULT_CLOCK_HZ,
            timeout_sec: VMWDT_DEFAULT_TIMEOUT_SEC,
        };

        fdt::create_fdt(
            AARCH64_FDT_MAX_SIZE as usize,
            &mem,
            pci_irqs,
            pci_cfg,
            &pci_ranges,
            dev_resources,
            vcpu_count as u32,
            components.cpu_clusters,
            components.cpu_capacity,
            components.cpu_frequencies,
            fdt_offset,
            cmdline.as_str(),
            (payload.entry(), payload.size() as usize),
            initrd,
            components.android_fstab,
            irq_chip.get_vgic_version() == DeviceKind::ArmVgicV3,
            use_pmu,
            psci_version,
            components.swiotlb.map(|size| {
                (
                    get_swiotlb_addr(components.memory_size, vm.get_hypervisor()),
                    size,
                )
            }),
            bat_mmio_base_and_irq,
            vmwdt_cfg,
            dump_device_tree_blob,
            &|writer, phandles| vm.create_fdt(writer, phandles),
            components.dynamic_power_coefficient,
            device_tree_overlays,
        )
        .map_err(Error::CreateFdt)?;

        vm.init_arch(
            payload.entry(),
            fdt_offset,
            AARCH64_FDT_MAX_SIZE.try_into().unwrap(),
        )
        .map_err(Error::InitVmError)?;

        Ok(RunnableLinuxVm {
            vm,
            vcpu_count,
            vcpus: Some(vcpus),
            vcpu_init,
            vcpu_affinity: components.vcpu_affinity,
            no_smt: components.no_smt,
            irq_chip: irq_chip.try_box_clone().map_err(Error::CloneIrqChip)?,
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            suspend_evt,
            rt_cpus: components.rt_cpus,
            delay_rt: components.delay_rt,
            bat_control,
            #[cfg(feature = "gdb")]
            gdb: components.gdb,
            pm: None,
            resume_notify_devices: Vec::new(),
            root_config: pci_root,
            platform_devices,
            hotplug_bus: BTreeMap::new(),
            devices_thread: None,
            vm_request_tube: None,
        })
    }

    fn configure_vcpu<V: Vm>(
        _vm: &V,
        _hypervisor: &dyn Hypervisor,
        _irq_chip: &mut dyn IrqChipAArch64,
        vcpu: &mut dyn VcpuAArch64,
        vcpu_init: VcpuInitAArch64,
        _vcpu_id: usize,
        _num_cpus: usize,
        _cpu_config: Option<CpuConfigAArch64>,
    ) -> std::result::Result<(), Self::Error> {
        for (reg, value) in vcpu_init.regs.iter() {
            vcpu.set_one_reg(*reg, *value).map_err(Error::SetReg)?;
        }
        Ok(())
    }

    fn register_pci_device<V: VmAArch64, Vcpu: VcpuAArch64>(
        _linux: &mut RunnableLinuxVm<V, Vcpu>,
        _device: Box<dyn PciDevice>,
        _minijail: Option<Minijail>,
        _resources: &mut SystemAllocator,
        _tube: &mpsc::Sender<PciRootCommand>,
        #[cfg(feature = "swap")] _swap_controller: &mut Option<swap::SwapController>,
    ) -> std::result::Result<PciAddress, Self::Error> {
        // hotplug function isn't verified on AArch64, so set it unsupported here.
        Err(Error::Unsupported)
    }

    fn get_host_cpu_frequencies_khz() -> std::result::Result<BTreeMap<usize, Vec<u32>>, Self::Error>
    {
        Ok(
            Self::collect_for_each_cpu(base::logical_core_frequencies_khz)
                .map_err(Error::CpuFrequencies)?
                .into_iter()
                .enumerate()
                .collect(),
        )
    }

    // Returns a (cpu_id -> value) map of the DMIPS/MHz capacities of logical cores
    // in the host system.
    fn get_host_cpu_capacity() -> std::result::Result<BTreeMap<usize, u32>, Self::Error> {
        Ok(Self::collect_for_each_cpu(base::logical_core_capacity)
            .map_err(Error::CpuTopology)?
            .into_iter()
            .enumerate()
            .collect())
    }

    // Creates CPU cluster mask for each CPU in the host system.
    fn get_host_cpu_clusters() -> std::result::Result<Vec<CpuSet>, Self::Error> {
        let cluster_ids = Self::collect_for_each_cpu(base::logical_core_cluster_id)
            .map_err(Error::CpuTopology)?;
        Ok(cluster_ids
            .iter()
            .map(|&vcpu_cluster_id| {
                cluster_ids
                    .iter()
                    .enumerate()
                    .filter(|(_, &cpu_cluster_id)| vcpu_cluster_id == cpu_cluster_id)
                    .map(|(cpu_id, _)| cpu_id)
                    .collect()
            })
            .collect())
    }
}

#[cfg(feature = "gdb")]
impl<T: VcpuAArch64> arch::GdbOps<T> for AArch64 {
    type Error = Error;

    fn read_memory(
        _vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0; len];

        guest_mem
            .read_exact_at_addr(&mut buf, vaddr)
            .map_err(Error::ReadGuestMemory)?;

        Ok(buf)
    }

    fn write_memory(
        _vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        buf: &[u8],
    ) -> Result<()> {
        guest_mem
            .write_all_at_addr(buf, vaddr)
            .map_err(Error::WriteGuestMemory)
    }

    fn read_registers(vcpu: &T) -> Result<<GdbArch as Arch>::Registers> {
        let mut regs: <GdbArch as Arch>::Registers = Default::default();

        vcpu.get_gdb_registers(&mut regs).map_err(Error::ReadRegs)?;

        Ok(regs)
    }

    fn write_registers(vcpu: &T, regs: &<GdbArch as Arch>::Registers) -> Result<()> {
        vcpu.set_gdb_registers(regs).map_err(Error::WriteRegs)
    }

    fn read_register(vcpu: &T, reg_id: <GdbArch as Arch>::RegId) -> Result<Vec<u8>> {
        let mut reg = vec![0; std::mem::size_of::<u128>()];
        let size = vcpu
            .get_gdb_register(reg_id, reg.as_mut_slice())
            .map_err(Error::ReadReg)?;
        reg.truncate(size);
        Ok(reg)
    }

    fn write_register(vcpu: &T, reg_id: <GdbArch as Arch>::RegId, data: &[u8]) -> Result<()> {
        vcpu.set_gdb_register(reg_id, data).map_err(Error::WriteReg)
    }

    fn enable_singlestep(vcpu: &T) -> Result<()> {
        const SINGLE_STEP: bool = true;
        vcpu.set_guest_debug(&[], SINGLE_STEP)
            .map_err(Error::EnableSinglestep)
    }

    fn get_max_hw_breakpoints(vcpu: &T) -> Result<usize> {
        vcpu.get_max_hw_bps().map_err(Error::GetMaxHwBreakPoint)
    }

    fn set_hw_breakpoints(vcpu: &T, breakpoints: &[GuestAddress]) -> Result<()> {
        const SINGLE_STEP: bool = false;
        vcpu.set_guest_debug(breakpoints, SINGLE_STEP)
            .map_err(Error::SetHwBreakpoint)
    }
}

impl AArch64 {
    /// This returns a base part of the kernel command for this architecture
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(base::pagesize());
        cmdline.insert_str("panic=-1").unwrap();
        cmdline
    }

    /// Returns a system resource allocator configuration.
    ///
    /// # Arguments
    ///
    /// * `memory_end` - The first address beyond the end of guest memory.
    /// * `guest_phys_addr_bits` - Size of guest physical addresses (IPA) in bits.
    fn get_resource_allocator_config(
        memory_end: GuestAddress,
        guest_phys_addr_bits: u8,
    ) -> SystemAllocatorConfig {
        let guest_phys_end = 1u64 << guest_phys_addr_bits;
        // The platform MMIO region is immediately past the end of RAM.
        let plat_mmio_base = memory_end.offset();
        let plat_mmio_size = AARCH64_PLATFORM_MMIO_SIZE;
        // The high MMIO region is the rest of the address space after the platform MMIO region.
        let high_mmio_base = plat_mmio_base + plat_mmio_size;
        let high_mmio_size = guest_phys_end
            .checked_sub(high_mmio_base)
            .unwrap_or_else(|| {
                panic!(
                    "guest_phys_end {:#x} < high_mmio_base {:#x}",
                    guest_phys_end, high_mmio_base,
                );
            });
        SystemAllocatorConfig {
            io: None,
            low_mmio: AddressRange::from_start_and_size(AARCH64_MMIO_BASE, AARCH64_MMIO_SIZE)
                .expect("invalid mmio region"),
            high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
                .expect("invalid high mmio region"),
            platform_mmio: Some(
                AddressRange::from_start_and_size(plat_mmio_base, plat_mmio_size)
                    .expect("invalid platform mmio region"),
            ),
            first_irq: AARCH64_IRQ_BASE,
        }
    }

    /// This adds any early platform devices for this architecture.
    ///
    /// # Arguments
    ///
    /// * `irq_chip` - The IRQ chip to add irqs to.
    /// * `bus` - The bus to add devices to.
    /// * `vcpu_count` - The number of virtual CPUs for this guest VM
    /// * `vm_evt_wrtube` - The notification channel
    fn add_arch_devs(
        irq_chip: &mut dyn IrqChip,
        bus: &Bus,
        vcpu_count: usize,
        vm_evt_wrtube: &SendTube,
    ) -> Result<()> {
        let rtc_evt = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let rtc = devices::pl030::Pl030::new(rtc_evt.try_clone().map_err(Error::CloneEvent)?);
        irq_chip
            .register_edge_irq_event(AARCH64_RTC_IRQ, &rtc_evt, IrqEventSource::from_device(&rtc))
            .map_err(Error::RegisterIrqfd)?;

        bus.insert(
            Arc::new(Mutex::new(rtc)),
            AARCH64_RTC_ADDR,
            AARCH64_RTC_SIZE,
        )
        .expect("failed to add rtc device");

        let vm_wdt = Arc::new(Mutex::new(
            devices::vmwdt::Vmwdt::new(vcpu_count, vm_evt_wrtube.try_clone().unwrap()).unwrap(),
        ));
        bus.insert(vm_wdt, AARCH64_VMWDT_ADDR, AARCH64_VMWDT_SIZE)
            .expect("failed to add vmwdt device");

        Ok(())
    }

    /// Get ARM-specific features for vcpu with index `vcpu_id`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - The VM's index for `vcpu`.
    /// * `use_pmu` - Should `vcpu` be configured to use the Performance Monitor Unit.
    fn vcpu_features(vcpu_id: usize, use_pmu: bool) -> Vec<VcpuFeature> {
        let mut features = vec![VcpuFeature::PsciV0_2];
        if use_pmu {
            features.push(VcpuFeature::PmuV3);
        }
        // Non-boot cpus are powered off initially
        if vcpu_id != 0 {
            features.push(VcpuFeature::PowerOff);
        }

        features
    }

    /// Get initial register state for vcpu with index `vcpu_id`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - The VM's index for `vcpu`.
    fn vcpu_init(
        vcpu_id: usize,
        payload: &PayloadType,
        fdt_address: GuestAddress,
        protection_type: ProtectionType,
    ) -> VcpuInitAArch64 {
        let mut regs: BTreeMap<VcpuRegAArch64, u64> = Default::default();

        // All interrupts masked
        let pstate = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1H;
        regs.insert(VcpuRegAArch64::Pstate, pstate);

        // Other cpus are powered off initially
        if vcpu_id == 0 {
            let entry_addr = if protection_type.loads_firmware() {
                Some(AARCH64_PROTECTED_VM_FW_START)
            } else if protection_type.runs_firmware() {
                None // Initial PC value is set by the hypervisor
            } else {
                Some(payload.entry().offset())
            };

            /* PC -- entry point */
            if let Some(entry) = entry_addr {
                regs.insert(VcpuRegAArch64::Pc, entry);
            }

            /* X0 -- fdt address */
            regs.insert(VcpuRegAArch64::X(0), fdt_address.offset());

            if protection_type.runs_firmware() {
                /* X1 -- payload entry point */
                regs.insert(VcpuRegAArch64::X(1), payload.entry().offset());

                /* X2 -- image size */
                regs.insert(VcpuRegAArch64::X(2), payload.size());
            }
        }

        VcpuInitAArch64 { regs }
    }

    fn collect_for_each_cpu<F, T>(func: F) -> std::result::Result<Vec<T>, base::Error>
    where
        F: Fn(usize) -> std::result::Result<T, base::Error>,
    {
        (0..base::number_of_logical_cores()?).map(func).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_init_unprotected_kernel() {
        let payload = PayloadType::Kernel(LoadedKernel {
            address_range: AddressRange::from_start_and_size(0x8080_0000, 0x1000).unwrap(),
            size: 0x1000,
            entry: GuestAddress(0x8080_0000),
        });
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Unprotected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot);

        // PC: kernel image entry point
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::Pc), Some(&0x8080_0000));

        // X0: fdt_offset
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::X(0)), Some(&0x1234));
    }

    #[test]
    fn vcpu_init_unprotected_bios() {
        let payload = PayloadType::Bios {
            entry: GuestAddress(0x8020_0000),
            image_size: 0x1000,
        };
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Unprotected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot);

        // PC: bios image entry point
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::Pc), Some(&0x8020_0000));

        // X0: fdt_offset
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::X(0)), Some(&0x1234));
    }

    #[test]
    fn vcpu_init_protected_kernel() {
        let payload = PayloadType::Kernel(LoadedKernel {
            address_range: AddressRange::from_start_and_size(0x8080_0000, 0x1000).unwrap(),
            size: 0x1000,
            entry: GuestAddress(0x8080_0000),
        });
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Protected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot);

        // The hypervisor provides the initial value of PC, so PC should not be present in the
        // vcpu_init register map.
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::Pc), None);

        // X0: fdt_offset
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::X(0)), Some(&0x1234));

        // X1: kernel image entry point
        assert_eq!(
            vcpu_init.regs.get(&VcpuRegAArch64::X(1)),
            Some(&0x8080_0000)
        );

        // X2: image size
        assert_eq!(vcpu_init.regs.get(&VcpuRegAArch64::X(2)), Some(&0x1000));
    }
}
