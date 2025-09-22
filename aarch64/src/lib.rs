// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ARM 64-bit architecture support.

#![cfg(any(target_arch = "arm", target_arch = "aarch64"))]

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use std::sync::Arc;

#[cfg(feature = "gdb")]
use aarch64_sys_reg::AArch64SysRegId;
use arch::get_serial_cmdline;
use arch::CpuSet;
use arch::DtbOverlay;
use arch::FdtPosition;
use arch::GetSerialCmdlineError;
use arch::MemoryRegionConfig;
use arch::RunnableLinuxVm;
use arch::SveConfig;
use arch::VcpuAffinity;
use arch::VmComponents;
use arch::VmImage;
use base::MemoryMappingBuilder;
use base::SendTube;
use base::Tube;
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
#[cfg(any(target_os = "android", target_os = "linux"))]
use devices::VirtCpufreqV2;
use fdt::PciAddressSpace;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::reg::id::AArch64RegId;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
use hypervisor::CpuConfigAArch64;
use hypervisor::DeviceKind;
use hypervisor::Hypervisor;
use hypervisor::HypervisorCap;
use hypervisor::MemCacheType;
use hypervisor::ProtectionType;
use hypervisor::VcpuAArch64;
use hypervisor::VcpuFeature;
use hypervisor::VcpuInitAArch64;
use hypervisor::VcpuRegAArch64;
use hypervisor::Vm;
use hypervisor::VmAArch64;
use hypervisor::VmCap;
#[cfg(windows)]
use jail::FakeMinijailStub as Minijail;
use kernel_loader::LoadedKernel;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use remain::sorted;
use resources::address_allocator::AddressAllocator;
use resources::AddressRange;
use resources::MmioType;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_control::BatControl;
use vm_control::BatteryType;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use vm_memory::MemoryRegionOptions;
use vm_memory::MemoryRegionPurpose;

mod fdt;

const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;
const AARCH64_FDT_ALIGN: u64 = 0x200000;
const AARCH64_INITRD_ALIGN: u64 = 0x1000000;

// Maximum Linux arm64 kernel command line size (arch/arm64/include/uapi/asm/setup.h).
const AARCH64_CMDLINE_MAX_SIZE: usize = 2048;

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// This indicates the start of DRAM inside the physical address space.
const AARCH64_PHYS_MEM_START: u64 = 0x80000000;
const AARCH64_PLATFORM_MMIO_SIZE: u64 = 0x800000;

const AARCH64_PROTECTED_VM_FW_MAX_SIZE: u64 = 0x400000;
const AARCH64_PROTECTED_VM_FW_START: u64 =
    AARCH64_PHYS_MEM_START - AARCH64_PROTECTED_VM_FW_MAX_SIZE;

const AARCH64_PVTIME_IPA_MAX_SIZE: u64 = 0x10000;
const AARCH64_PVTIME_IPA_START: u64 = 0x1ff0000;
const AARCH64_PVTIME_SIZE: u64 = 64;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
const AARCH64_GIC_ITS_BASE: u64 = 0x40000000;
const AARCH64_GIC_ITS_SIZE: u64 = 0x20000;

// PSR (Processor State Register) bits
const PSR_MODE_EL1H: u64 = 0x00000005;
const PSR_F_BIT: u64 = 0x00000040;
const PSR_I_BIT: u64 = 0x00000080;
const PSR_A_BIT: u64 = 0x00000100;
const PSR_D_BIT: u64 = 0x00000200;

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

// Default PCI MMIO configuration region base address.
const AARCH64_PCI_CAM_BASE_DEFAULT: u64 = 0x10000;
// Default PCI MMIO configuration region size.
const AARCH64_PCI_CAM_SIZE_DEFAULT: u64 = 0x1000000;
// Default PCI mem base address.
const AARCH64_PCI_MEM_BASE_DEFAULT: u64 = 0x2000000;
// Default PCI mem size.
const AARCH64_PCI_MEM_SIZE_DEFAULT: u64 = 0x2000000;
// Virtio devices start at SPI interrupt number 4
const AARCH64_IRQ_BASE: u32 = 4;

// Virtual CPU Frequency Device.
const AARCH64_VIRTFREQ_BASE: u64 = 0x1040000;
const AARCH64_VIRTFREQ_SIZE: u64 = 0x8;
const AARCH64_VIRTFREQ_MAXSIZE: u64 = 0x10000;
const AARCH64_VIRTFREQ_V2_SIZE: u64 = 0x1000;

// PMU PPI interrupt, same as qemu
const AARCH64_PMU_IRQ: u32 = 7;

// VCPU stall detector interrupt
const AARCH64_VMWDT_IRQ: u32 = 15;

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

    fn address_range(&self) -> AddressRange {
        match self {
            Self::Bios { entry, image_size } => {
                AddressRange::from_start_and_size(entry.offset(), *image_size)
                    .expect("invalid BIOS address range")
            }
            Self::Kernel(k) => {
                // TODO: b/389759119: use `k.address_range` to include regions that are present in
                // memory but not in the original image file (e.g. `.bss` section).
                AddressRange::from_start_and_size(k.entry.offset(), k.size)
                    .expect("invalid kernel address range")
            }
        }
    }
}

// When static swiotlb allocation is required, returns the address it should be allocated at.
// Otherwise, returns None.
fn get_swiotlb_addr(
    memory_size: u64,
    swiotlb_size: u64,
    hypervisor: &(impl Hypervisor + ?Sized),
) -> Option<GuestAddress> {
    if hypervisor.check_capability(HypervisorCap::StaticSwiotlbAllocationRequired) {
        Some(GuestAddress(
            AARCH64_PHYS_MEM_START + memory_size - swiotlb_size,
        ))
    } else {
        None
    }
}

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
    #[error("bad PCI CAM configuration: {0}")]
    ConfigurePciCam(String),
    #[error("bad PCI mem configuration: {0}")]
    ConfigurePciMem(String),
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
    #[error("failed to create tube: {0}")]
    CreateTube(base::TubeError),
    #[error("failed to create VCPU: {0}")]
    CreateVcpu(base::Error),
    #[error("unable to create vm watchdog timer device: {0}")]
    CreateVmwdtDevice(anyhow::Error),
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
    InitVmError(anyhow::Error),
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

fn load_kernel(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    mut kernel_image: &mut File,
) -> Result<LoadedKernel> {
    if let Ok(elf_kernel) = kernel_loader::load_elf(
        guest_mem,
        kernel_start,
        &mut kernel_image,
        AARCH64_PHYS_MEM_START,
    ) {
        return Ok(elf_kernel);
    }

    if let Ok(lz4_kernel) =
        kernel_loader::load_arm64_kernel_lz4(guest_mem, kernel_start, &mut kernel_image)
    {
        return Ok(lz4_kernel);
    }

    kernel_loader::load_arm64_kernel(guest_mem, kernel_start, kernel_image)
        .map_err(Error::KernelLoadFailure)
}

pub struct AArch64;

fn get_block_size() -> u64 {
    let page_size = base::pagesize();
    // Each PTE entry being 8 bytes long, we can fit in one page (page_size / 8)
    // entries.
    let ptes_per_page = page_size / 8;
    let block_size = page_size * ptes_per_page;

    block_size as u64
}

fn get_vcpu_mpidr_aff<Vcpu: VcpuAArch64>(vcpus: &[Vcpu], index: usize) -> Option<u64> {
    const MPIDR_AFF_MASK: u64 = 0xff_00ff_ffff;

    Some(vcpus.get(index)?.get_mpidr().ok()? & MPIDR_AFF_MASK)
}

fn main_memory_size(components: &VmComponents, hypervisor: &(impl Hypervisor + ?Sized)) -> u64 {
    // Static swiotlb is allocated from the end of RAM as a separate memory region, so, if
    // enabled, make the RAM memory region smaller to leave room for it.
    let mut main_memory_size = components.memory_size;
    if let Some(size) = components.swiotlb {
        if hypervisor.check_capability(HypervisorCap::StaticSwiotlbAllocationRequired) {
            main_memory_size -= size;
        }
    }
    main_memory_size
}

pub struct ArchMemoryLayout {
    pci_cam: AddressRange,
    pci_mem: AddressRange,
}

impl arch::LinuxArch for AArch64 {
    type Error = Error;
    type ArchMemoryLayout = ArchMemoryLayout;

    fn arch_memory_layout(
        components: &VmComponents,
    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error> {
        let (pci_cam_start, pci_cam_size) = match components.pci_config.cam {
            Some(MemoryRegionConfig { start, size }) => {
                (start, size.unwrap_or(AARCH64_PCI_CAM_SIZE_DEFAULT))
            }
            None => (AARCH64_PCI_CAM_BASE_DEFAULT, AARCH64_PCI_CAM_SIZE_DEFAULT),
        };
        // TODO: Make the PCI slot allocator aware of the CAM size so we can remove this check.
        if pci_cam_size != AARCH64_PCI_CAM_SIZE_DEFAULT {
            return Err(Error::ConfigurePciCam(format!(
                "PCI CAM size must be {AARCH64_PCI_CAM_SIZE_DEFAULT:#x}, got {pci_cam_size:#x}"
            )));
        }
        let pci_cam = AddressRange::from_start_and_size(pci_cam_start, pci_cam_size).ok_or(
            Error::ConfigurePciCam("PCI CAM region overflowed".to_string()),
        )?;
        if pci_cam.end >= AARCH64_PHYS_MEM_START {
            return Err(Error::ConfigurePciCam(format!(
                "PCI CAM ({pci_cam:?}) must be before start of RAM ({AARCH64_PHYS_MEM_START:#x})"
            )));
        }

        let pci_mem = match components.pci_config.mem {
            Some(MemoryRegionConfig { start, size }) => AddressRange::from_start_and_size(
                start,
                size.unwrap_or(AARCH64_PCI_MEM_SIZE_DEFAULT),
            )
            .ok_or(Error::ConfigurePciMem("region overflowed".to_string()))?,
            None => AddressRange::from_start_and_size(
                AARCH64_PCI_MEM_BASE_DEFAULT,
                AARCH64_PCI_MEM_SIZE_DEFAULT,
            )
            .unwrap(),
        };

        Ok(ArchMemoryLayout { pci_cam, pci_mem })
    }

    /// Returns a Vec of the valid memory addresses.
    /// These should be used to configure the GuestMemory structure for the platform.
    fn guest_memory_layout(
        components: &VmComponents,
        _arch_memory_layout: &Self::ArchMemoryLayout,
        hypervisor: &impl Hypervisor,
    ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
        let main_memory_size = main_memory_size(components, hypervisor);

        let mut memory_regions = vec![(
            GuestAddress(AARCH64_PHYS_MEM_START),
            main_memory_size,
            MemoryRegionOptions::new().align(get_block_size()),
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
            if let Some(addr) = get_swiotlb_addr(components.memory_size, size, hypervisor) {
                memory_regions.push((
                    addr,
                    size,
                    MemoryRegionOptions::new().purpose(MemoryRegionPurpose::StaticSwiotlbRegion),
                ));
            }
        }

        Ok(memory_regions)
    }

    fn get_system_allocator_config<V: Vm>(
        vm: &V,
        arch_memory_layout: &Self::ArchMemoryLayout,
    ) -> SystemAllocatorConfig {
        let guest_phys_end = 1u64 << vm.get_guest_phys_addr_bits();
        // The platform MMIO region is immediately past the end of RAM.
        let plat_mmio_base = vm.get_memory().end_addr().offset();
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
            low_mmio: arch_memory_layout.pci_mem,
            high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
                .expect("invalid high mmio region"),
            platform_mmio: Some(
                AddressRange::from_start_and_size(plat_mmio_base, plat_mmio_size)
                    .expect("invalid platform mmio region"),
            ),
            first_irq: AARCH64_IRQ_BASE,
        }
    }

    fn build_vm<V, Vcpu>(
        mut components: VmComponents,
        arch_memory_layout: &Self::ArchMemoryLayout,
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
        _guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
        device_tree_overlays: Vec<DtbOverlay>,
        fdt_position: Option<FdtPosition>,
        no_pmu: bool,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmAArch64,
        Vcpu: VcpuAArch64,
    {
        let has_bios = matches!(components.vm_image, VmImage::Bios(_));
        let mem = vm.get_memory().clone();

        let main_memory_size = main_memory_size(&components, vm.get_hypervisor());

        // Load pvmfw early because it tells the hypervisor this is a pVM which affects
        // the behavior of calls like Hypervisor::check_capability
        if components.hv_cfg.protection_type.needs_firmware_loaded() {
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

        let fdt_position = fdt_position.unwrap_or(if has_bios {
            FdtPosition::Start
        } else {
            FdtPosition::End
        });
        let payload_address = match fdt_position {
            // If FDT is at the start RAM, the payload needs to go somewhere after it.
            FdtPosition::Start => GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_FDT_MAX_SIZE),
            // Otherwise, put the payload at the start of RAM.
            FdtPosition::End | FdtPosition::AfterPayload => GuestAddress(AARCH64_PHYS_MEM_START),
        };

        // separate out image loading from other setup to get a specific error for
        // image loading
        let mut initrd = None;
        let (payload, payload_end_address) = match components.vm_image {
            VmImage::Bios(ref mut bios) => {
                let image_size = arch::load_image(&mem, bios, payload_address, u64::MAX)
                    .map_err(Error::BiosLoadFailure)?;
                (
                    PayloadType::Bios {
                        entry: payload_address,
                        image_size: image_size as u64,
                    },
                    payload_address
                        .checked_add(image_size.try_into().unwrap())
                        .and_then(|end| end.checked_sub(1))
                        .unwrap(),
                )
            }
            VmImage::Kernel(ref mut kernel_image) => {
                let loaded_kernel = load_kernel(&mem, payload_address, kernel_image)?;
                let kernel_end = loaded_kernel.address_range.end;
                let mut payload_end = GuestAddress(kernel_end);
                initrd = match components.initrd_image {
                    Some(initrd_file) => {
                        let mut initrd_file = initrd_file;
                        let initrd_addr = (kernel_end + 1 + (AARCH64_INITRD_ALIGN - 1))
                            & !(AARCH64_INITRD_ALIGN - 1);
                        let initrd_max_size =
                            main_memory_size.saturating_sub(initrd_addr - AARCH64_PHYS_MEM_START);
                        let initrd_addr = GuestAddress(initrd_addr);
                        let initrd_size =
                            arch::load_image(&mem, &mut initrd_file, initrd_addr, initrd_max_size)
                                .map_err(Error::InitrdLoadFailure)?;
                        payload_end = initrd_addr
                            .checked_add(initrd_size.try_into().unwrap())
                            .and_then(|end| end.checked_sub(1))
                            .unwrap();
                        Some((initrd_addr, initrd_size))
                    }
                    None => None,
                };
                (PayloadType::Kernel(loaded_kernel), payload_end)
            }
        };

        let memory_end = GuestAddress(AARCH64_PHYS_MEM_START + main_memory_size);

        let fdt_address = match fdt_position {
            FdtPosition::Start => GuestAddress(AARCH64_PHYS_MEM_START),
            FdtPosition::End => {
                let addr = memory_end
                    .checked_sub(AARCH64_FDT_MAX_SIZE)
                    .expect("Not enough memory for FDT")
                    .align_down(AARCH64_FDT_ALIGN);
                assert!(addr > payload_end_address, "Not enough memory for FDT");
                addr
            }
            FdtPosition::AfterPayload => payload_end_address
                .checked_add(1)
                .and_then(|addr| addr.align(AARCH64_FDT_ALIGN))
                .expect("Not enough memory for FDT"),
        };

        let mut use_pmu = vm.check_capability(VmCap::ArmPmuV3);
        use_pmu &= !no_pmu;
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
                    fdt_address,
                    components.hv_cfg.protection_type,
                    components.boot_cpu,
                )
            };
            has_pvtime &= vcpu.has_pvtime_support();
            vcpus.push(vcpu);
            vcpu_ids.push(vcpu_id);
            vcpu_init.push(per_vcpu_init);
        }

        if components.sve_config.auto {
            components.sve_config.enable = vm.check_capability(VmCap::Sve);
        }

        // Initialize Vcpus after all Vcpu objects have been created.
        for (vcpu_id, vcpu) in vcpus.iter().enumerate() {
            let features =
                &Self::vcpu_features(vcpu_id, use_pmu, components.boot_cpu, components.sve_config);
            vcpu.init(features).map_err(Error::VcpuInit)?;
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
                MemCacheType::CacheCoherent,
            )
            .map_err(Error::MapPvtimeError)?;
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
        let (suspend_tube_send, suspend_tube_recv) =
            Tube::directional_pair().map_err(Error::CreateTube)?;
        let suspend_tube_send = Arc::new(Mutex::new(suspend_tube_send));

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
                GuestAddress(arch_memory_layout.pci_cam.start),
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

        let (vmwdt_host_tube, vmwdt_control_tube) = Tube::pair().map_err(Error::CreateTube)?;
        Self::add_arch_devs(
            irq_chip.as_irq_chip_mut(),
            &mmio_bus,
            vcpu_count,
            _vm_evt_wrtube,
            vmwdt_control_tube,
        )?;

        let com_evt_1_3 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let serial_devices = arch::add_serial_devices(
            components.hv_cfg.protection_type,
            &mmio_bus,
            (AARCH64_SERIAL_1_3_IRQ, com_evt_1_3.get_trigger()),
            (AARCH64_SERIAL_2_4_IRQ, com_evt_2_4.get_trigger()),
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
            .insert(
                pci_bus,
                arch_memory_layout.pci_cam.start,
                arch_memory_layout.pci_cam.len().unwrap(),
            )
            .map_err(Error::RegisterPci)?;

        let (vcpufreq_host_tube, vcpufreq_control_tube) =
            Tube::pair().map_err(Error::CreateTube)?;
        let vcpufreq_shared_tube = Arc::new(Mutex::new(vcpufreq_control_tube));
        #[cfg(any(target_os = "android", target_os = "linux"))]
        if !components.cpu_frequencies.is_empty() {
            let mut freq_domain_vcpus: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
            let mut freq_domain_perfs: BTreeMap<u32, Arc<AtomicU32>> = BTreeMap::new();
            let mut vcpu_affinities: Vec<u32> = Vec::new();
            for vcpu in 0..vcpu_count {
                let freq_domain = *components.vcpu_domains.get(&vcpu).unwrap_or(&(vcpu as u32));
                freq_domain_vcpus.entry(freq_domain).or_default().push(vcpu);
                let vcpu_affinity = match components.vcpu_affinity.clone() {
                    Some(VcpuAffinity::Global(v)) => v,
                    Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&vcpu).unwrap_or_default(),
                    None => panic!("vcpu_affinity needs to be set for VirtCpufreq"),
                };
                vcpu_affinities.push(vcpu_affinity[0].try_into().unwrap());
            }
            for domain in freq_domain_vcpus.keys() {
                let domain_perf = Arc::new(AtomicU32::new(0));
                freq_domain_perfs.insert(*domain, domain_perf);
            }
            let largest_vcpu_affinity_idx = *vcpu_affinities.iter().max().unwrap() as usize;
            for (vcpu, vcpu_affinity) in vcpu_affinities.iter().enumerate() {
                let mut virtfreq_size = AARCH64_VIRTFREQ_SIZE;
                if components.virt_cpufreq_v2 {
                    let domain = *components.vcpu_domains.get(&vcpu).unwrap_or(&(vcpu as u32));
                    virtfreq_size = AARCH64_VIRTFREQ_V2_SIZE;
                    let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreqV2::new(
                        *vcpu_affinity,
                        components.cpu_frequencies.get(&vcpu).unwrap().clone(),
                        components.vcpu_domain_paths.get(&vcpu).cloned(),
                        domain,
                        *components.normalized_cpu_ipc_ratios.get(&vcpu).unwrap(),
                        largest_vcpu_affinity_idx,
                        vcpufreq_shared_tube.clone(),
                        freq_domain_vcpus.get(&domain).unwrap().clone(),
                        freq_domain_perfs.get(&domain).unwrap().clone(),
                    )));
                    mmio_bus
                        .insert(
                            virt_cpufreq,
                            AARCH64_VIRTFREQ_BASE + (vcpu as u64 * virtfreq_size),
                            virtfreq_size,
                        )
                        .map_err(Error::RegisterVirtCpufreq)?;
                } else {
                    let virt_cpufreq = Arc::new(Mutex::new(VirtCpufreq::new(
                        *vcpu_affinity,
                        *components.cpu_capacity.get(&vcpu).unwrap(),
                        *components
                            .cpu_frequencies
                            .get(&vcpu)
                            .unwrap()
                            .iter()
                            .max()
                            .unwrap(),
                    )));
                    mmio_bus
                        .insert(
                            virt_cpufreq,
                            AARCH64_VIRTFREQ_BASE + (vcpu as u64 * virtfreq_size),
                            virtfreq_size,
                        )
                        .map_err(Error::RegisterVirtCpufreq)?;
                }

                if vcpu as u64 * AARCH64_VIRTFREQ_SIZE + virtfreq_size > AARCH64_VIRTFREQ_MAXSIZE {
                    panic!("Exceeded maximum number of virt cpufreq devices");
                }
            }
        }

        let mut cmdline = Self::get_base_linux_cmdline();
        get_serial_cmdline(&mut cmdline, serial_parameters, "mmio", &serial_devices)
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
            base: arch_memory_layout.pci_cam.start,
            size: arch_memory_layout.pci_cam.len().unwrap(),
        };

        let mut pci_ranges: Vec<fdt::PciRange> = Vec::new();

        let mut add_pci_ranges =
            |alloc: &AddressAllocator, space: PciAddressSpace, prefetchable: bool| {
                pci_ranges.extend(alloc.pools().iter().map(|range| fdt::PciRange {
                    space,
                    bus_address: range.start,
                    cpu_physical_address: range.start,
                    size: range.len().unwrap(),
                    prefetchable,
                }));
            };

        add_pci_ranges(
            system_allocator.mmio_allocator(MmioType::Low),
            PciAddressSpace::Memory,
            false, // prefetchable
        );
        add_pci_ranges(
            system_allocator.mmio_allocator(MmioType::High),
            PciAddressSpace::Memory64,
            true, // prefetchable
        );

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
            &|n| get_vcpu_mpidr_aff(&vcpus, n),
            components.cpu_clusters,
            components.cpu_capacity,
            components.cpu_frequencies,
            fdt_address,
            cmdline
                .as_str_with_max_len(AARCH64_CMDLINE_MAX_SIZE - 1)
                .map_err(Error::Cmdline)?,
            payload.address_range(),
            initrd,
            components.android_fstab,
            irq_chip.get_vgic_version() == DeviceKind::ArmVgicV3,
            irq_chip.has_vgic_its(),
            use_pmu,
            psci_version,
            components.swiotlb.map(|size| {
                (
                    get_swiotlb_addr(components.memory_size, size, vm.get_hypervisor()),
                    size,
                )
            }),
            bat_mmio_base_and_irq,
            vmwdt_cfg,
            dump_device_tree_blob,
            &|writer, phandles| vm.create_fdt(writer, phandles),
            components.dynamic_power_coefficient,
            device_tree_overlays,
            &serial_devices,
            components.virt_cpufreq_v2,
        )
        .map_err(Error::CreateFdt)?;

        vm.init_arch(
            payload.entry(),
            fdt_address,
            AARCH64_FDT_MAX_SIZE.try_into().unwrap(),
        )
        .map_err(Error::InitVmError)?;

        let vm_request_tubes = vec![vmwdt_host_tube, vcpufreq_host_tube];

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
            suspend_tube: (suspend_tube_send, suspend_tube_recv),
            rt_cpus: components.rt_cpus,
            delay_rt: components.delay_rt,
            bat_control,
            pm: None,
            resume_notify_devices: Vec::new(),
            root_config: pci_root,
            platform_devices,
            hotplug_bus: BTreeMap::new(),
            devices_thread: None,
            vm_request_tubes,
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

    fn get_host_cpu_max_freq_khz() -> std::result::Result<BTreeMap<usize, u32>, Self::Error> {
        Ok(Self::collect_for_each_cpu(base::logical_core_max_freq_khz)
            .map_err(Error::CpuFrequencies)?
            .into_iter()
            .enumerate()
            .collect())
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
        let mut unique_clusters: Vec<CpuSet> = cluster_ids
            .iter()
            .map(|&vcpu_cluster_id| {
                cluster_ids
                    .iter()
                    .enumerate()
                    .filter(|(_, &cpu_cluster_id)| vcpu_cluster_id == cpu_cluster_id)
                    .map(|(cpu_id, _)| cpu_id)
                    .collect()
            })
            .collect();
        unique_clusters.sort_unstable();
        unique_clusters.dedup();
        Ok(unique_clusters)
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
        assert!(
            regs.x.len() == 31,
            "unexpected number of Xn general purpose registers"
        );
        for (i, reg) in regs.x.iter_mut().enumerate() {
            let n = u8::try_from(i).expect("invalid Xn general purpose register index");
            *reg = vcpu
                .get_one_reg(VcpuRegAArch64::X(n))
                .map_err(Error::ReadReg)?;
        }
        regs.sp = vcpu
            .get_one_reg(VcpuRegAArch64::Sp)
            .map_err(Error::ReadReg)?;
        regs.pc = vcpu
            .get_one_reg(VcpuRegAArch64::Pc)
            .map_err(Error::ReadReg)?;
        // hypervisor API gives a 64-bit value for Pstate, but GDB wants a 32-bit "CPSR".
        regs.cpsr = vcpu
            .get_one_reg(VcpuRegAArch64::Pstate)
            .map_err(Error::ReadReg)? as u32;
        for (i, reg) in regs.v.iter_mut().enumerate() {
            let n = u8::try_from(i).expect("invalid Vn general purpose register index");
            *reg = vcpu.get_vector_reg(n).map_err(Error::ReadReg)?;
        }
        regs.fpcr = vcpu
            .get_one_reg(VcpuRegAArch64::System(aarch64_sys_reg::FPCR))
            .map_err(Error::ReadReg)? as u32;
        regs.fpsr = vcpu
            .get_one_reg(VcpuRegAArch64::System(aarch64_sys_reg::FPSR))
            .map_err(Error::ReadReg)? as u32;

        Ok(regs)
    }

    fn write_registers(vcpu: &T, regs: &<GdbArch as Arch>::Registers) -> Result<()> {
        assert!(
            regs.x.len() == 31,
            "unexpected number of Xn general purpose registers"
        );
        for (i, reg) in regs.x.iter().enumerate() {
            let n = u8::try_from(i).expect("invalid Xn general purpose register index");
            vcpu.set_one_reg(VcpuRegAArch64::X(n), *reg)
                .map_err(Error::WriteReg)?;
        }
        vcpu.set_one_reg(VcpuRegAArch64::Sp, regs.sp)
            .map_err(Error::WriteReg)?;
        vcpu.set_one_reg(VcpuRegAArch64::Pc, regs.pc)
            .map_err(Error::WriteReg)?;
        // GDB gives a 32-bit value for "CPSR", but hypervisor API wants a 64-bit Pstate.
        let pstate = vcpu
            .get_one_reg(VcpuRegAArch64::Pstate)
            .map_err(Error::ReadReg)?;
        let pstate = (pstate & 0xffff_ffff_0000_0000) | (regs.cpsr as u64);
        vcpu.set_one_reg(VcpuRegAArch64::Pstate, pstate)
            .map_err(Error::WriteReg)?;
        for (i, reg) in regs.v.iter().enumerate() {
            let n = u8::try_from(i).expect("invalid Vn general purpose register index");
            vcpu.set_vector_reg(n, *reg).map_err(Error::WriteReg)?;
        }
        vcpu.set_one_reg(
            VcpuRegAArch64::System(aarch64_sys_reg::FPCR),
            u64::from(regs.fpcr),
        )
        .map_err(Error::WriteReg)?;
        vcpu.set_one_reg(
            VcpuRegAArch64::System(aarch64_sys_reg::FPSR),
            u64::from(regs.fpsr),
        )
        .map_err(Error::WriteReg)?;

        Ok(())
    }

    fn read_register(vcpu: &T, reg_id: <GdbArch as Arch>::RegId) -> Result<Vec<u8>> {
        let result = match reg_id {
            AArch64RegId::X(n) => vcpu
                .get_one_reg(VcpuRegAArch64::X(n))
                .map(|v| v.to_ne_bytes().to_vec()),
            AArch64RegId::Sp => vcpu
                .get_one_reg(VcpuRegAArch64::Sp)
                .map(|v| v.to_ne_bytes().to_vec()),
            AArch64RegId::Pc => vcpu
                .get_one_reg(VcpuRegAArch64::Pc)
                .map(|v| v.to_ne_bytes().to_vec()),
            AArch64RegId::Pstate => vcpu
                .get_one_reg(VcpuRegAArch64::Pstate)
                .map(|v| (v as u32).to_ne_bytes().to_vec()),
            AArch64RegId::V(n) => vcpu.get_vector_reg(n).map(|v| v.to_ne_bytes().to_vec()),
            AArch64RegId::System(op) => vcpu
                .get_one_reg(VcpuRegAArch64::System(AArch64SysRegId::from_encoded(op)))
                .map(|v| v.to_ne_bytes().to_vec()),
            _ => {
                base::error!("Unexpected AArch64RegId: {:?}", reg_id);
                Err(base::Error::new(libc::EINVAL))
            }
        };

        match result {
            Ok(bytes) => Ok(bytes),
            // ENOENT is returned when KVM is aware of the register but it is unavailable
            Err(e) if e.errno() == libc::ENOENT => Ok(Vec::new()),
            Err(e) => Err(Error::ReadReg(e)),
        }
    }

    fn write_register(vcpu: &T, reg_id: <GdbArch as Arch>::RegId, data: &[u8]) -> Result<()> {
        fn try_into_u32(data: &[u8]) -> Result<u32> {
            let s = data
                .get(..4)
                .ok_or(Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            let a = s
                .try_into()
                .map_err(|_| Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            Ok(u32::from_ne_bytes(a))
        }

        fn try_into_u64(data: &[u8]) -> Result<u64> {
            let s = data
                .get(..8)
                .ok_or(Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            let a = s
                .try_into()
                .map_err(|_| Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            Ok(u64::from_ne_bytes(a))
        }

        fn try_into_u128(data: &[u8]) -> Result<u128> {
            let s = data
                .get(..16)
                .ok_or(Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            let a = s
                .try_into()
                .map_err(|_| Error::WriteReg(base::Error::new(libc::EINVAL)))?;
            Ok(u128::from_ne_bytes(a))
        }

        match reg_id {
            AArch64RegId::X(n) => vcpu.set_one_reg(VcpuRegAArch64::X(n), try_into_u64(data)?),
            AArch64RegId::Sp => vcpu.set_one_reg(VcpuRegAArch64::Sp, try_into_u64(data)?),
            AArch64RegId::Pc => vcpu.set_one_reg(VcpuRegAArch64::Pc, try_into_u64(data)?),
            AArch64RegId::Pstate => {
                vcpu.set_one_reg(VcpuRegAArch64::Pstate, u64::from(try_into_u32(data)?))
            }
            AArch64RegId::V(n) => vcpu.set_vector_reg(n, try_into_u128(data)?),
            AArch64RegId::System(op) => vcpu.set_one_reg(
                VcpuRegAArch64::System(AArch64SysRegId::from_encoded(op)),
                try_into_u64(data)?,
            ),
            _ => {
                base::error!("Unexpected AArch64RegId: {:?}", reg_id);
                Err(base::Error::new(libc::EINVAL))
            }
        }
        .map_err(Error::WriteReg)
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
        let mut cmdline = kernel_cmdline::Cmdline::new();
        cmdline.insert_str("panic=-1").unwrap();
        cmdline
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
        vmwdt_request_tube: Tube,
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

        let vmwdt_evt = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let vm_wdt = devices::vmwdt::Vmwdt::new(
            vcpu_count,
            vm_evt_wrtube.try_clone().unwrap(),
            vmwdt_evt.try_clone().map_err(Error::CloneEvent)?,
            vmwdt_request_tube,
        )
        .map_err(Error::CreateVmwdtDevice)?;
        irq_chip
            .register_edge_irq_event(
                AARCH64_VMWDT_IRQ,
                &vmwdt_evt,
                IrqEventSource::from_device(&vm_wdt),
            )
            .map_err(Error::RegisterIrqfd)?;

        bus.insert(
            Arc::new(Mutex::new(vm_wdt)),
            AARCH64_VMWDT_ADDR,
            AARCH64_VMWDT_SIZE,
        )
        .expect("failed to add vmwdt device");

        Ok(())
    }

    /// Get ARM-specific features for vcpu with index `vcpu_id`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - The VM's index for `vcpu`.
    /// * `use_pmu` - Should `vcpu` be configured to use the Performance Monitor Unit.
    fn vcpu_features(
        vcpu_id: usize,
        use_pmu: bool,
        boot_cpu: usize,
        sve: SveConfig,
    ) -> Vec<VcpuFeature> {
        let mut features = vec![VcpuFeature::PsciV0_2];
        if use_pmu {
            features.push(VcpuFeature::PmuV3);
        }
        // Non-boot cpus are powered off initially
        if vcpu_id != boot_cpu {
            features.push(VcpuFeature::PowerOff);
        }
        if sve.enable {
            features.push(VcpuFeature::Sve);
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
        boot_cpu: usize,
    ) -> VcpuInitAArch64 {
        let mut regs: BTreeMap<VcpuRegAArch64, u64> = Default::default();

        // All interrupts masked
        let pstate = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1H;
        regs.insert(VcpuRegAArch64::Pstate, pstate);

        // Other cpus are powered off initially
        if vcpu_id == boot_cpu {
            let entry_addr = if protection_type.needs_firmware_loaded() {
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
            class: kernel_loader::ElfClass::ElfClass64,
        });
        assert_eq!(
            payload.address_range(),
            AddressRange {
                start: 0x8080_0000,
                end: 0x8080_0fff
            }
        );
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Unprotected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot, 0);

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
        assert_eq!(
            payload.address_range(),
            AddressRange {
                start: 0x8020_0000,
                end: 0x8020_0fff
            }
        );
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Unprotected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot, 0);

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
            class: kernel_loader::ElfClass::ElfClass64,
        });
        assert_eq!(
            payload.address_range(),
            AddressRange {
                start: 0x8080_0000,
                end: 0x8080_0fff
            }
        );
        let fdt_address = GuestAddress(0x1234);
        let prot = ProtectionType::Protected;

        let vcpu_init = AArch64::vcpu_init(0, &payload, fdt_address, prot, 0);

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
