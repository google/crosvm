// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! x86 architecture support.

#![cfg(target_arch = "x86_64")]

mod fdt;

#[cfg(feature = "gdb")]
mod gdb;

const SETUP_DTB: u32 = 2;
const SETUP_RNG_SEED: u32 = 9;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod bootparam;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(clippy::all)]
mod mpspec;

pub mod multiboot_spec;

pub mod acpi;
mod bzimage;
pub mod cpuid;
mod gdt;
pub mod interrupts;
pub mod mptable;
pub mod regs;
pub mod smbios;

use std::arch::x86_64::CpuidResult;
use std::cmp::min;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::mem;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use acpi_tables::sdt::SDT;
use anyhow::Context;
use arch::get_serial_cmdline;
use arch::serial::SerialDeviceInfo;
use arch::CpuSet;
use arch::DtbOverlay;
use arch::FdtPosition;
use arch::GetSerialCmdlineError;
use arch::MemoryRegionConfig;
use arch::PciConfig;
use arch::RunnableLinuxVm;
use arch::VmComponents;
use arch::VmImage;
use base::debug;
use base::info;
use base::warn;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::AsRawDescriptors;
use base::Event;
use base::FileGetLen;
use base::FileReadWriteAtVolatile;
use base::SendTube;
use base::Tube;
use base::TubeError;
use chrono::Utc;
pub use cpuid::adjust_cpuid;
pub use cpuid::CpuIdContext;
use devices::acpi::PM_WAKEUP_GPIO;
use devices::Bus;
use devices::BusDevice;
use devices::BusDeviceObj;
use devices::BusResumeDevice;
use devices::BusType;
use devices::Debugcon;
use devices::FwCfgParameters;
use devices::IrqChip;
use devices::IrqChipX86_64;
use devices::IrqEventSource;
use devices::PciAddress;
use devices::PciConfigIo;
use devices::PciConfigMmio;
use devices::PciDevice;
use devices::PciInterruptPin;
use devices::PciRoot;
use devices::PciRootCommand;
use devices::PciVirtualConfigMmio;
use devices::Pflash;
#[cfg(any(target_os = "android", target_os = "linux"))]
use devices::ProxyDevice;
use devices::Serial;
use devices::SerialHardware;
use devices::SerialParameters;
use devices::VirtualPmc;
use devices::FW_CFG_BASE_PORT;
use devices::FW_CFG_MAX_FILE_SLOTS;
use devices::FW_CFG_WIDTH;
use hypervisor::CpuConfigX86_64;
use hypervisor::Hypervisor;
use hypervisor::HypervisorX86_64;
use hypervisor::ProtectionType;
use hypervisor::VcpuInitX86_64;
use hypervisor::VcpuX86_64;
use hypervisor::Vm;
use hypervisor::VmCap;
use hypervisor::VmX86_64;
#[cfg(feature = "seccomp_trace")]
use jail::read_jail_addr;
#[cfg(windows)]
use jail::FakeMinijailStub as Minijail;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use mptable::MPTABLE_RANGE;
use multiboot_spec::MultibootInfo;
use multiboot_spec::MultibootMmapEntry;
use multiboot_spec::MULTIBOOT_BOOTLOADER_MAGIC;
use rand::rngs::OsRng;
use rand::RngCore;
use remain::sorted;
use resources::AddressRange;
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
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::bootparam::boot_params;
use crate::bootparam::setup_header;
use crate::bootparam::XLF_CAN_BE_LOADED_ABOVE_4G;
use crate::cpuid::EDX_HYBRID_CPU_SHIFT;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("error allocating a single gpe")]
    AllocateGpe,
    #[error("error allocating IO resource: {0}")]
    AllocateIOResouce(resources::Error),
    #[error("error allocating a single irq")]
    AllocateIrq,
    #[error("unable to clone an Event: {0}")]
    CloneEvent(base::Error),
    #[error("failed to clone IRQ chip: {0}")]
    CloneIrqChip(base::Error),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("failed to clone jail: {0}")]
    CloneJail(minijail::Error),
    #[error("unable to clone a Tube: {0}")]
    CloneTube(TubeError),
    #[error("the given kernel command line was invalid: {0}")]
    Cmdline(kernel_cmdline::Error),
    #[error("failed writing command line to guest memory")]
    CommandLineCopy,
    #[error("command line overflowed guest memory")]
    CommandLineOverflow,
    #[error("failed to configure hotplugged pci device: {0}")]
    ConfigurePciDevice(arch::DeviceRegistrationError),
    #[error("bad PCI ECAM configuration: {0}")]
    ConfigurePciEcam(String),
    #[error("bad PCI mem configuration: {0}")]
    ConfigurePciMem(String),
    #[error("failed to configure segment registers: {0}")]
    ConfigureSegments(regs::Error),
    #[error("error configuring the system")]
    ConfigureSystem,
    #[error("unable to create ACPI tables")]
    CreateAcpi,
    #[error("unable to create battery devices: {0}")]
    CreateBatDevices(arch::DeviceRegistrationError),
    #[error("could not create debugcon device: {0}")]
    CreateDebugconDevice(devices::SerialError),
    #[error("unable to make an Event: {0}")]
    CreateEvent(base::Error),
    #[error("failed to create fdt: {0}")]
    CreateFdt(cros_fdt::Error),
    #[error("failed to create fw_cfg device: {0}")]
    CreateFwCfgDevice(devices::FwCfgError),
    #[error("failed to create IOAPIC device: {0}")]
    CreateIoapicDevice(base::Error),
    #[error("failed to create a PCI root hub: {0}")]
    CreatePciRoot(arch::DeviceRegistrationError),
    #[error("unable to create PIT: {0}")]
    CreatePit(base::Error),
    #[error("unable to make PIT device: {0}")]
    CreatePitDevice(devices::PitError),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("unable to create proxy device: {0}")]
    CreateProxyDevice(devices::ProxyError),
    #[error("unable to create serial devices: {0}")]
    CreateSerialDevices(arch::DeviceRegistrationError),
    #[error("failed to create socket: {0}")]
    CreateSocket(io::Error),
    #[error("failed to create tube: {0}")]
    CreateTube(base::TubeError),
    #[error("failed to create VCPU: {0}")]
    CreateVcpu(base::Error),
    #[error("DTB size is larger than the allowed size")]
    DTBSizeGreaterThanAllowed,
    #[error("invalid e820 setup params")]
    E820Configuration,
    #[error("failed to enable singlestep execution: {0}")]
    EnableSinglestep(base::Error),
    #[error("failed to enable split irqchip: {0}")]
    EnableSplitIrqchip(base::Error),
    #[error("failed to get serial cmdline: {0}")]
    GetSerialCmdline(GetSerialCmdlineError),
    #[error("failed to insert device onto bus: {0}")]
    InsertBus(devices::BusError),
    #[error("the kernel extends past the end of RAM")]
    InvalidCpuConfig,
    #[error("invalid CPU config parameters")]
    KernelOffsetPastEnd,
    #[error("error loading bios: {0}")]
    LoadBios(io::Error),
    #[error("error loading kernel bzImage: {0}")]
    LoadBzImage(bzimage::Error),
    #[error("error loading custom pVM firmware: {0}")]
    LoadCustomPvmFw(arch::LoadImageError),
    #[error("error loading initrd: {0}")]
    LoadInitrd(arch::LoadImageError),
    #[error("error loading Kernel: {0}")]
    LoadKernel(kernel_loader::Error),
    #[error("error loading pflash: {0}")]
    LoadPflash(io::Error),
    #[error("error loading pVM firmware: {0}")]
    LoadPvmFw(base::Error),
    #[error("error in multiboot_info setup")]
    MultibootInfoSetup,
    #[error("error translating address: Page not present")]
    PageNotPresent,
    #[error("pci mmio overlaps with pVM firmware memory")]
    PciMmioOverlapPvmFw,
    #[error("pVM firmware not supported when bios is used on x86_64")]
    PvmFwBiosUnsupported,
    #[error("error reading guest memory {0}")]
    ReadingGuestMemory(vm_memory::GuestMemoryError),
    #[error("single register read not supported on x86_64")]
    ReadRegIsUnsupported,
    #[error("error reading CPU registers {0}")]
    ReadRegs(base::Error),
    #[error("error registering an IrqFd: {0}")]
    RegisterIrqfd(base::Error),
    #[error("error registering virtual socket device: {0}")]
    RegisterVsock(arch::DeviceRegistrationError),
    #[error("error reserved pcie config mmio")]
    ReservePcieCfgMmio(resources::Error),
    #[error("failed to set a hardware breakpoint: {0}")]
    SetHwBreakpoint(base::Error),
    #[error("failed to set identity map addr: {0}")]
    SetIdentityMapAddr(base::Error),
    #[error("failed to set interrupts: {0}")]
    SetLint(interrupts::Error),
    #[error("failed to set tss addr: {0}")]
    SetTssAddr(base::Error),
    #[error("failed to set up cmos: {0}")]
    SetupCmos(anyhow::Error),
    #[error("failed to set up cpuid: {0}")]
    SetupCpuid(cpuid::Error),
    #[error("setup data too large")]
    SetupDataTooLarge,
    #[error("failed to set up FPU: {0}")]
    SetupFpu(base::Error),
    #[error("failed to set up guest memory: {0}")]
    SetupGuestMemory(GuestMemoryError),
    #[error("failed to set up mptable: {0}")]
    SetupMptable(mptable::Error),
    #[error("failed to set up MSRs: {0}")]
    SetupMsrs(base::Error),
    #[error("failed to set up page tables: {0}")]
    SetupPageTables(regs::Error),
    #[error("failed to set up pflash: {0}")]
    SetupPflash(anyhow::Error),
    #[error("failed to set up registers: {0}")]
    SetupRegs(regs::Error),
    #[error("failed to set up SMBIOS: {0}")]
    SetupSmbios(smbios::Error),
    #[error("failed to set up sregs: {0}")]
    SetupSregs(base::Error),
    #[error("too many vCPUs")]
    TooManyVcpus,
    #[error("failed to translate virtual address")]
    TranslatingVirtAddr,
    #[error("protected VMs not supported on x86_64")]
    UnsupportedProtectionType,
    #[error("single register write not supported on x86_64")]
    WriteRegIsUnsupported,
    #[error("error writing CPU registers {0}")]
    WriteRegs(base::Error),
    #[error("error writing guest memory {0}")]
    WritingGuestMemory(GuestMemoryError),
    #[error("error writing setup_data: {0}")]
    WritingSetupData(GuestMemoryError),
    #[error("the zero page extends past the end of guest_mem")]
    ZeroPagePastRamEnd,
    #[error("error writing the zero page of guest memory")]
    ZeroPageSetup,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct X8664arch;

// Like `bootparam::setup_data` without the incomplete array field at the end, which allows us to
// safely implement Copy, Clone
#[repr(C)]
#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct setup_data_hdr {
    pub next: u64,
    pub type_: u32,
    pub len: u32,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SetupDataType {
    Dtb = SETUP_DTB,
    RngSeed = SETUP_RNG_SEED,
}

/// A single entry to be inserted in the bootparam `setup_data` linked list.
pub struct SetupData {
    pub data: Vec<u8>,
    pub type_: SetupDataType,
}

impl SetupData {
    /// Returns the length of the data
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Collection of SetupData entries to be inserted in the
/// bootparam `setup_data` linked list.
pub struct SetupDataEntries {
    entries: Vec<SetupData>,
    setup_data_start: usize,
    setup_data_end: usize,
    available_size: usize,
}

impl SetupDataEntries {
    /// Returns a new instance of SetupDataEntries
    pub fn new(setup_data_start: usize, setup_data_end: usize) -> SetupDataEntries {
        SetupDataEntries {
            entries: Vec::new(),
            setup_data_start,
            setup_data_end,
            available_size: setup_data_end - setup_data_start,
        }
    }

    /// Adds a new SetupDataEntry and returns the remaining size available
    pub fn insert(&mut self, setup_data: SetupData) -> usize {
        self.available_size -= setup_data.size();
        self.entries.push(setup_data);

        self.available_size
    }

    /// Copy setup_data entries to guest memory and link them together with the `next` field.
    /// Returns the guest address of the first entry in the setup_data list, if any.
    pub fn write_setup_data(&self, guest_mem: &GuestMemory) -> Result<Option<GuestAddress>> {
        write_setup_data(
            guest_mem,
            GuestAddress(self.setup_data_start as u64),
            GuestAddress(self.setup_data_end as u64),
            &self.entries,
        )
    }
}

#[derive(Copy, Clone, Debug)]
enum E820Type {
    Ram = 0x01,
    Reserved = 0x2,
}

#[derive(Copy, Clone, Debug)]
struct E820Entry {
    pub address: GuestAddress,
    pub len: u64,
    pub mem_type: E820Type,
}

const KB: u64 = 1 << 10;
const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;

pub const BOOT_STACK_POINTER: u64 = 0x8000;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
// Make sure it align to 256MB for MTRR convenient
const MEM_32BIT_GAP_SIZE: u64 = 768 * MB;
// Reserved memory for nand_bios/LAPIC/IOAPIC/HPET/.....
const RESERVED_MEM_SIZE: u64 = 0x800_0000;
const DEFAULT_PCI_MEM_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
// Reserve 64MB for pcie enhanced configuration
const DEFAULT_PCIE_CFG_MMIO_SIZE: u64 = 0x400_0000;
const DEFAULT_PCIE_CFG_MMIO_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
const DEFAULT_PCIE_CFG_MMIO_START: u64 = DEFAULT_PCIE_CFG_MMIO_END - DEFAULT_PCIE_CFG_MMIO_SIZE + 1;
// Linux (with 4-level paging) has a physical memory limit of 46 bits (64 TiB).
const HIGH_MMIO_MAX_END: u64 = (1u64 << 46) - 1;
pub const KERNEL_32BIT_ENTRY_OFFSET: u64 = 0x0;
pub const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;
pub const MULTIBOOT_INFO_OFFSET: u64 = 0x6000;
pub const MULTIBOOT_INFO_SIZE: u64 = 0x1000;
pub const ZERO_PAGE_OFFSET: u64 = 0x7000;
// Set BIOS max size to 16M: this is used only when `unrestricted guest` is disabled
const BIOS_MAX_SIZE: u64 = 0x1000000;

pub const KERNEL_START_OFFSET: u64 = 0x20_0000;
const CMDLINE_OFFSET: u64 = 0x2_0000;
const CMDLINE_MAX_SIZE: u64 = 0x800; // including terminating zero
const SETUP_DATA_START: u64 = CMDLINE_OFFSET + CMDLINE_MAX_SIZE;
const SETUP_DATA_END: u64 = MPTABLE_RANGE.start;
const X86_64_FDT_MAX_SIZE: u64 = 0x4000;
const X86_64_SERIAL_1_3_IRQ: u32 = 4;
const X86_64_SERIAL_2_4_IRQ: u32 = 3;
// X86_64_SCI_IRQ is used to fill the ACPI FACP table.
// The sci_irq number is better to be a legacy
// IRQ number which is less than 16(actually most of the
// platforms have fixed IRQ number 9). So we can
// reserve the IRQ number 5 for SCI and let the
// the other devices starts from next.
pub const X86_64_SCI_IRQ: u32 = 5;
// The CMOS RTC uses IRQ 8; start allocating IRQs at 9.
pub const X86_64_IRQ_BASE: u32 = 9;
const ACPI_HI_RSDP_WINDOW_BASE: u64 = 0x000E_0000;

// pVM firmware memory. Should be within the low 4GB, so that it is identity-mapped
// by setup_page_tables() when a protected VM boots in long mode, since the pVM firmware is
// the VM entry point.
const PROTECTED_VM_FW_MAX_SIZE: u64 = 0x40_0000;
// Load the pVM firmware just below 2 GB to allow use of `-mcmodel=small`.
const PROTECTED_VM_FW_START: u64 = 0x8000_0000 - PROTECTED_VM_FW_MAX_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum CpuManufacturer {
    Intel,
    Amd,
    Unknown,
}

pub fn get_cpu_manufacturer() -> CpuManufacturer {
    cpuid::cpu_manufacturer()
}

pub struct ArchMemoryLayout {
    // the pci mmio range below 4G
    pci_mmio_before_32bit: AddressRange,
    // the pcie cfg mmio range
    pcie_cfg_mmio: AddressRange,
    // the pVM firmware memory (if running a protected VM)
    pvmfw_mem: Option<AddressRange>,
}

pub fn create_arch_memory_layout(
    pci_config: &PciConfig,
    has_protected_vm_firmware: bool,
) -> Result<ArchMemoryLayout> {
    // the max bus number is 256 and each bus occupy 1MB, so the max pcie cfg mmio size = 256M
    const MAX_PCIE_ECAM_SIZE: u64 = 256 * MB;
    let pcie_cfg_mmio = match pci_config.ecam {
        Some(MemoryRegionConfig {
            start,
            size: Some(size),
        }) => AddressRange::from_start_and_size(start, size.min(MAX_PCIE_ECAM_SIZE)).unwrap(),
        Some(MemoryRegionConfig { start, size: None }) => {
            AddressRange::from_start_and_end(start, DEFAULT_PCIE_CFG_MMIO_END)
        }
        None => {
            AddressRange::from_start_and_end(DEFAULT_PCIE_CFG_MMIO_START, DEFAULT_PCIE_CFG_MMIO_END)
        }
    };
    if pcie_cfg_mmio.start % pcie_cfg_mmio.len().unwrap() != 0
        || pcie_cfg_mmio.start % MB != 0
        || pcie_cfg_mmio.len().unwrap() % MB != 0
    {
        return Err(Error::ConfigurePciEcam(
            "base and len must be aligned to 1MB and base must be a multiple of len".to_string(),
        ));
    }
    if pcie_cfg_mmio.end >= 0x1_0000_0000 {
        return Err(Error::ConfigurePciEcam(
            "end address can't go beyond 4G".to_string(),
        ));
    }

    let pci_mmio_before_32bit = match pci_config.mem {
        Some(MemoryRegionConfig {
            start,
            size: Some(size),
        }) => AddressRange::from_start_and_size(start, size)
            .ok_or(Error::ConfigurePciMem("region overflowed".to_string()))?,
        Some(MemoryRegionConfig { start, size: None }) => {
            AddressRange::from_start_and_end(start, DEFAULT_PCI_MEM_END)
        }
        None => AddressRange::from_start_and_end(
            pcie_cfg_mmio
                .start
                .min(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE),
            DEFAULT_PCI_MEM_END,
        ),
    };

    let pvmfw_mem = if has_protected_vm_firmware {
        let range = AddressRange {
            start: PROTECTED_VM_FW_START,
            end: PROTECTED_VM_FW_START + PROTECTED_VM_FW_MAX_SIZE - 1,
        };
        if !pci_mmio_before_32bit.intersect(range).is_empty() {
            return Err(Error::PciMmioOverlapPvmFw);
        }

        Some(range)
    } else {
        None
    };

    Ok(ArchMemoryLayout {
        pci_mmio_before_32bit,
        pcie_cfg_mmio,
        pvmfw_mem,
    })
}

/// The x86 reset vector for i386+ and x86_64 puts the processor into an "unreal mode" where it
/// can access the last 1 MB of the 32-bit address space in 16-bit mode, and starts the instruction
/// pointer at the effective physical address 0xFFFF_FFF0.
fn bios_start(bios_size: u64) -> GuestAddress {
    GuestAddress(FIRST_ADDR_PAST_32BITS - bios_size)
}

fn identity_map_addr_start() -> GuestAddress {
    // Set Identity map address 4 pages before the max BIOS size
    GuestAddress(FIRST_ADDR_PAST_32BITS - BIOS_MAX_SIZE - 4 * 0x1000)
}

fn tss_addr_start() -> GuestAddress {
    // Set TSS address one page after identity map address
    GuestAddress(identity_map_addr_start().offset() + 0x1000)
}

fn tss_addr_end() -> GuestAddress {
    // Set TSS address section to have 3 pages
    GuestAddress(tss_addr_start().offset() + 0x3000)
}

fn configure_boot_params(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    setup_data: Option<GuestAddress>,
    initrd: Option<(GuestAddress, usize)>,
    mut params: boot_params,
    e820_entries: &[E820Entry],
) -> Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x100_0000; // Must be non-zero.

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.ext_cmd_line_ptr = (cmdline_addr.offset() >> 32) as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(setup_data) = setup_data {
        params.hdr.setup_data = setup_data.offset();
    }
    if let Some((initrd_addr, initrd_size)) = initrd {
        params.hdr.ramdisk_image = initrd_addr.offset() as u32;
        params.ext_ramdisk_image = (initrd_addr.offset() >> 32) as u32;
        params.hdr.ramdisk_size = initrd_size as u32;
        params.ext_ramdisk_size = (initrd_size as u64 >> 32) as u32;
    }

    if e820_entries.len() >= params.e820_table.len() {
        return Err(Error::E820Configuration);
    }

    for (src, dst) in e820_entries.iter().zip(params.e820_table.iter_mut()) {
        dst.addr = src.address.offset();
        dst.size = src.len;
        dst.type_ = src.mem_type as u32;
    }
    params.e820_entries = e820_entries.len() as u8;

    let zero_page_addr = GuestAddress(ZERO_PAGE_OFFSET);
    if !guest_mem.is_valid_range(zero_page_addr, mem::size_of::<boot_params>() as u64) {
        return Err(Error::ZeroPagePastRamEnd);
    }

    guest_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

fn configure_multiboot_info(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    e820_entries: &[E820Entry],
) -> Result<()> {
    let mut multiboot_info = MultibootInfo {
        ..Default::default()
    };

    // Extra Multiboot-related data is added directly after the info structure.
    let mut multiboot_data_addr =
        GuestAddress(MULTIBOOT_INFO_OFFSET + mem::size_of_val(&multiboot_info) as u64);
    multiboot_data_addr = multiboot_data_addr
        .align(16)
        .ok_or(Error::MultibootInfoSetup)?;

    // mem_lower is the amount of RAM below 1 MB, in units of KiB.
    let mem_lower = guest_mem
        .regions()
        .filter(|r| {
            r.options.purpose == MemoryRegionPurpose::GuestMemoryRegion
                && r.guest_addr.offset() < 1 * MB
        })
        .map(|r| r.size as u64)
        .sum::<u64>()
        / KB;

    // mem_upper is the amount of RAM above 1 MB up to the first memory hole, in units of KiB.
    // We don't have the ISA 15-16 MB hole, so this includes all RAM from 1 MB up to the
    // beginning of the PCI hole just below 4 GB.
    let mem_upper = guest_mem
        .regions()
        .filter(|r| {
            r.options.purpose == MemoryRegionPurpose::GuestMemoryRegion
                && r.guest_addr.offset() >= 1 * MB
                && r.guest_addr.offset() < 4 * GB
        })
        .map(|r| r.size as u64)
        .sum::<u64>()
        / KB;

    multiboot_info.mem_lower = mem_lower as u32;
    multiboot_info.mem_upper = mem_upper as u32;
    multiboot_info.flags |= MultibootInfo::F_MEM;

    // Memory map - convert from params.e820_table to Multiboot format.
    let multiboot_mmap: Vec<MultibootMmapEntry> = e820_entries
        .iter()
        .map(|e820_entry| MultibootMmapEntry {
            size: 20, // size of the entry, not including the size field itself
            base_addr: e820_entry.address.offset(),
            length: e820_entry.len,
            type_: e820_entry.mem_type as u32,
        })
        .collect();
    let multiboot_mmap_bytes = multiboot_mmap.as_bytes();
    let multiboot_mmap_addr =
        append_multiboot_info(guest_mem, &mut multiboot_data_addr, multiboot_mmap_bytes)?;
    multiboot_info.mmap_addr = multiboot_mmap_addr.offset() as u32;
    multiboot_info.mmap_length = multiboot_mmap_bytes.len() as u32;
    multiboot_info.flags |= MultibootInfo::F_MMAP;

    // Command line
    multiboot_info.cmdline = cmdline_addr.offset() as u32;
    multiboot_info.flags |= MultibootInfo::F_CMDLINE;

    // Boot loader name
    let boot_loader_name_addr =
        append_multiboot_info(guest_mem, &mut multiboot_data_addr, b"crosvm\0")?;
    multiboot_info.boot_loader_name = boot_loader_name_addr.offset() as u32;
    multiboot_info.flags |= MultibootInfo::F_BOOT_LOADER_NAME;

    guest_mem
        .write_obj_at_addr(multiboot_info, GuestAddress(MULTIBOOT_INFO_OFFSET))
        .map_err(|_| Error::MultibootInfoSetup)?;

    Ok(())
}

fn append_multiboot_info(
    guest_mem: &GuestMemory,
    addr: &mut GuestAddress,
    data: &[u8],
) -> Result<GuestAddress> {
    let data_addr = *addr;
    let new_addr = addr
        .checked_add(data.len() as u64)
        .and_then(|a| a.align(16))
        .ok_or(Error::MultibootInfoSetup)?;

    // Make sure we don't write beyond the region reserved for Multiboot info.
    if new_addr.offset() - MULTIBOOT_INFO_OFFSET > MULTIBOOT_INFO_SIZE {
        return Err(Error::MultibootInfoSetup);
    }

    guest_mem
        .write_all_at_addr(data, data_addr)
        .map_err(|_| Error::MultibootInfoSetup)?;

    *addr = new_addr;
    Ok(data_addr)
}

/// Write setup_data entries in guest memory and link them together with the `next` field.
///
/// Returns the guest address of the first entry in the setup_data list, if any.
fn write_setup_data(
    guest_mem: &GuestMemory,
    setup_data_start: GuestAddress,
    setup_data_end: GuestAddress,
    setup_data: &[SetupData],
) -> Result<Option<GuestAddress>> {
    let mut setup_data_list_head = None;

    // Place the first setup_data at the first 64-bit aligned offset following setup_data_start.
    let mut setup_data_addr = setup_data_start.align(8).ok_or(Error::SetupDataTooLarge)?;

    let mut entry_iter = setup_data.iter().peekable();
    while let Some(entry) = entry_iter.next() {
        if setup_data_list_head.is_none() {
            setup_data_list_head = Some(setup_data_addr);
        }

        // Ensure the entry (header plus data) fits into guest memory.
        let entry_size = (mem::size_of::<setup_data_hdr>() + entry.data.len()) as u64;
        let entry_end = setup_data_addr
            .checked_add(entry_size)
            .ok_or(Error::SetupDataTooLarge)?;

        if entry_end >= setup_data_end {
            return Err(Error::SetupDataTooLarge);
        }

        let next_setup_data_addr = if entry_iter.peek().is_some() {
            // Place the next setup_data at a 64-bit aligned address.
            setup_data_addr
                .checked_add(entry_size)
                .and_then(|addr| addr.align(8))
                .ok_or(Error::SetupDataTooLarge)?
        } else {
            // This is the final entry. Terminate the list with next == 0.
            GuestAddress(0)
        };

        let hdr = setup_data_hdr {
            next: next_setup_data_addr.offset(),
            type_: entry.type_ as u32,
            len: entry
                .data
                .len()
                .try_into()
                .map_err(|_| Error::SetupDataTooLarge)?,
        };

        guest_mem
            .write_obj_at_addr(hdr, setup_data_addr)
            .map_err(Error::WritingSetupData)?;
        guest_mem
            .write_all_at_addr(
                &entry.data,
                setup_data_addr.unchecked_add(mem::size_of::<setup_data_hdr>() as u64),
            )
            .map_err(Error::WritingSetupData)?;

        setup_data_addr = next_setup_data_addr;
    }

    Ok(setup_data_list_head)
}

/// Find the first `setup_data_hdr` with the given type in guest memory and return its address.
fn find_setup_data(
    mem: &GuestMemory,
    setup_data_start: GuestAddress,
    setup_data_end: GuestAddress,
    type_: SetupDataType,
) -> Option<GuestAddress> {
    let mut setup_data_addr = setup_data_start.align(8)?;
    while setup_data_addr < setup_data_end {
        let hdr: setup_data_hdr = mem.read_obj_from_addr(setup_data_addr).ok()?;
        if hdr.type_ == type_ as u32 {
            return Some(setup_data_addr);
        }

        if hdr.next == 0 {
            return None;
        }

        setup_data_addr = GuestAddress(hdr.next);
    }
    None
}

/// Generate a SETUP_RNG_SEED SetupData with random seed data.
fn setup_data_rng_seed() -> SetupData {
    let mut data = vec![0u8; 256];
    OsRng.fill_bytes(&mut data);
    SetupData {
        data,
        type_: SetupDataType::RngSeed,
    }
}

/// Add an e820 region to the e820 map.
fn add_e820_entry(
    e820_entries: &mut Vec<E820Entry>,
    range: AddressRange,
    mem_type: E820Type,
) -> Result<()> {
    e820_entries.push(E820Entry {
        address: GuestAddress(range.start),
        len: range.len().ok_or(Error::E820Configuration)?,
        mem_type,
    });

    Ok(())
}

/// Generate a memory map in INT 0x15 AX=0xE820 format.
fn generate_e820_memory_map(
    arch_memory_layout: &ArchMemoryLayout,
    guest_mem: &GuestMemory,
) -> Result<Vec<E820Entry>> {
    let mut e820_entries = Vec::new();

    for r in guest_mem.regions() {
        let range = AddressRange::from_start_and_size(r.guest_addr.offset(), r.size as u64)
            .expect("invalid guest mem region");
        let mem_type = match r.options.purpose {
            MemoryRegionPurpose::Bios => E820Type::Reserved,
            MemoryRegionPurpose::GuestMemoryRegion => E820Type::Ram,
            // After the pVM firmware jumped to the guest, the pVM firmware itself is no longer
            // running, so its memory is reusable by the guest OS. So add this memory as RAM rather
            // than Reserved.
            MemoryRegionPurpose::ProtectedFirmwareRegion => E820Type::Ram,
            MemoryRegionPurpose::ReservedMemory => E820Type::Reserved,
        };
        add_e820_entry(&mut e820_entries, range, mem_type)?;
    }

    let pcie_cfg_mmio_range = arch_memory_layout.pcie_cfg_mmio;
    add_e820_entry(&mut e820_entries, pcie_cfg_mmio_range, E820Type::Reserved)?;

    add_e820_entry(
        &mut e820_entries,
        X8664arch::get_pcie_vcfg_mmio_range(guest_mem, &pcie_cfg_mmio_range),
        E820Type::Reserved,
    )?;

    // Reserve memory section for Identity map and TSS
    add_e820_entry(
        &mut e820_entries,
        AddressRange {
            start: identity_map_addr_start().offset(),
            end: tss_addr_end().offset() - 1,
        },
        E820Type::Reserved,
    )?;

    Ok(e820_entries)
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(
    arch_memory_layout: &ArchMemoryLayout,
    mem_size: u64,
    bios_size: Option<u64>,
) -> Vec<(GuestAddress, u64, MemoryRegionOptions)> {
    let mut regions = Vec::new();

    // Some guest kernels expect a typical PC memory layout where the region between 640 KB and
    // 1 MB is reserved for device memory/ROMs and get confused if there is a RAM region
    // spanning this area, so we provide the traditional 640 KB low memory and 1 MB+
    // high memory regions.
    let mem_below_1m = 640 * KB;
    regions.push((
        GuestAddress(0),
        mem_below_1m,
        MemoryRegionOptions::new().purpose(MemoryRegionPurpose::GuestMemoryRegion),
    ));

    // Reserved/BIOS data area between 640 KB and 1 MB.
    // This needs to be backed by an actual GuestMemory region so we can write BIOS tables here, but
    // it should be reported as "reserved" in the e820 memory map to match PC architecture
    // expectations.
    regions.push((
        GuestAddress(640 * KB),
        (1 * MB) - (640 * KB),
        MemoryRegionOptions::new().purpose(MemoryRegionPurpose::ReservedMemory),
    ));

    // RAM between 1 MB and 4 GB
    let mem_1m_to_4g = arch_memory_layout.pci_mmio_before_32bit.start.min(mem_size) - 1 * MB;
    regions.push((
        GuestAddress(1 * MB),
        mem_1m_to_4g,
        MemoryRegionOptions::new().purpose(MemoryRegionPurpose::GuestMemoryRegion),
    ));

    // RAM above 4 GB
    let mem_above_4g = mem_size.saturating_sub(1 * MB + mem_1m_to_4g);
    if mem_above_4g > 0 {
        regions.push((
            GuestAddress(FIRST_ADDR_PAST_32BITS),
            mem_above_4g,
            MemoryRegionOptions::new().purpose(MemoryRegionPurpose::GuestMemoryRegion),
        ));
    }

    if let Some(bios_size) = bios_size {
        regions.push((
            bios_start(bios_size),
            bios_size,
            MemoryRegionOptions::new().purpose(MemoryRegionPurpose::Bios),
        ));
    }

    if let Some(pvmfw_mem) = arch_memory_layout.pvmfw_mem {
        // Remove any areas of guest memory regions that overlap the pVM firmware range.
        while let Some(overlapping_region_index) = regions.iter().position(|(addr, size, _opts)| {
            let region_addr_range = AddressRange::from_start_and_size(addr.offset(), *size)
                .expect("invalid GuestMemory range");
            region_addr_range.overlaps(pvmfw_mem)
        }) {
            let overlapping_region = regions.swap_remove(overlapping_region_index);
            let overlapping_region_range = AddressRange::from_start_and_size(
                overlapping_region.0.offset(),
                overlapping_region.1,
            )
            .unwrap();
            let (first, second) = overlapping_region_range.non_overlapping_ranges(pvmfw_mem);
            if !first.is_empty() {
                regions.push((
                    GuestAddress(first.start),
                    first.len().unwrap(),
                    overlapping_region.2.clone(),
                ));
            }
            if !second.is_empty() {
                regions.push((
                    GuestAddress(second.start),
                    second.len().unwrap(),
                    overlapping_region.2,
                ));
            }
        }

        // Insert a region for the pVM firmware area.
        regions.push((
            GuestAddress(pvmfw_mem.start),
            pvmfw_mem.len().expect("invalid pvmfw region"),
            MemoryRegionOptions::new().purpose(MemoryRegionPurpose::ProtectedFirmwareRegion),
        ));
    }

    regions.sort_unstable_by_key(|(addr, _, _)| *addr);

    for (addr, size, options) in &regions {
        debug!(
            "{:#018x}-{:#018x} {:?}",
            addr.offset(),
            addr.offset() + size - 1,
            options.purpose,
        );
    }

    regions
}

impl arch::LinuxArch for X8664arch {
    type Error = Error;
    type ArchMemoryLayout = ArchMemoryLayout;

    fn arch_memory_layout(
        components: &VmComponents,
    ) -> std::result::Result<Self::ArchMemoryLayout, Self::Error> {
        create_arch_memory_layout(
            &components.pci_config,
            components.hv_cfg.protection_type.runs_firmware(),
        )
    }

    fn guest_memory_layout(
        components: &VmComponents,
        arch_memory_layout: &Self::ArchMemoryLayout,
        _hypervisor: &impl Hypervisor,
    ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
        let bios_size = match &components.vm_image {
            VmImage::Bios(bios_file) => Some(bios_file.metadata().map_err(Error::LoadBios)?.len()),
            VmImage::Kernel(_) => None,
        };

        Ok(arch_memory_regions(
            arch_memory_layout,
            components.memory_size,
            bios_size,
        ))
    }

    fn get_system_allocator_config<V: Vm>(
        vm: &V,
        arch_memory_layout: &Self::ArchMemoryLayout,
    ) -> SystemAllocatorConfig {
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xffff,
            }),
            low_mmio: arch_memory_layout.pci_mmio_before_32bit,
            high_mmio: Self::get_high_mmio_range(vm, arch_memory_layout),
            platform_mmio: None,
            first_irq: X86_64_IRQ_BASE,
        }
    }

    fn build_vm<V, Vcpu>(
        mut components: VmComponents,
        arch_memory_layout: &Self::ArchMemoryLayout,
        vm_evt_wrtube: &SendTube,
        system_allocator: &mut SystemAllocator,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        battery: (Option<BatteryType>, Option<Minijail>),
        mut vm: V,
        ramoops_region: Option<arch::pstore::RamoopsRegion>,
        devs: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
        irq_chip: &mut dyn IrqChipX86_64,
        vcpu_ids: &mut Vec<usize>,
        dump_device_tree_blob: Option<PathBuf>,
        debugcon_jail: Option<Minijail>,
        pflash_jail: Option<Minijail>,
        fw_cfg_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
        device_tree_overlays: Vec<DtbOverlay>,
        _fdt_position: Option<FdtPosition>,
        _no_pmu: bool,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmX86_64,
        Vcpu: VcpuX86_64,
    {
        let mem = vm.get_memory().clone();

        let vcpu_count = components.vcpu_count;

        vm.set_identity_map_addr(identity_map_addr_start())
            .map_err(Error::SetIdentityMapAddr)?;

        vm.set_tss_addr(tss_addr_start())
            .map_err(Error::SetTssAddr)?;

        // Use IRQ info in ACPI if provided by the user.
        let mut mptable = true;
        let mut sci_irq = X86_64_SCI_IRQ;

        // punch pcie config mmio from pci low mmio, so that it couldn't be
        // allocated to any device.
        let pcie_cfg_mmio_range = arch_memory_layout.pcie_cfg_mmio;
        system_allocator
            .reserve_mmio(pcie_cfg_mmio_range)
            .map_err(Error::ReservePcieCfgMmio)?;

        for sdt in components.acpi_sdts.iter() {
            if sdt.is_signature(b"FACP") {
                mptable = false;
                let sci_irq_fadt: u16 = sdt.read(acpi::FADT_FIELD_SCI_INTERRUPT);
                sci_irq = sci_irq_fadt.into();
                if !system_allocator.reserve_irq(sci_irq) {
                    warn!("sci irq {} already reserved.", sci_irq);
                }
            }
        }

        let pcie_vcfg_range = Self::get_pcie_vcfg_mmio_range(&mem, &pcie_cfg_mmio_range);
        let mmio_bus = Arc::new(Bus::new(BusType::Mmio));
        let io_bus = Arc::new(Bus::new(BusType::Io));

        let (pci_devices, _devs): (Vec<_>, Vec<_>) = devs
            .into_iter()
            .partition(|(dev, _)| dev.as_pci_device().is_some());

        let pci_devices = pci_devices
            .into_iter()
            .map(|(dev, jail_orig)| (dev.into_pci_device().unwrap(), jail_orig))
            .collect();

        let (pci, pci_irqs, pid_debug_label_map, amls, gpe_scope_amls) = arch::generate_pci_root(
            pci_devices,
            irq_chip.as_irq_chip_mut(),
            mmio_bus.clone(),
            GuestAddress(pcie_cfg_mmio_range.start),
            12,
            io_bus.clone(),
            system_allocator,
            &mut vm,
            4, // Share the four pin interrupts (INTx#)
            Some(pcie_vcfg_range.start),
            #[cfg(feature = "swap")]
            swap_controller,
        )
        .map_err(Error::CreatePciRoot)?;

        let pci = Arc::new(Mutex::new(pci));
        pci.lock().enable_pcie_cfg_mmio(pcie_cfg_mmio_range.start);
        let pci_cfg = PciConfigIo::new(
            pci.clone(),
            components.break_linux_pci_config_io,
            vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
        );
        let pci_bus = Arc::new(Mutex::new(pci_cfg));
        io_bus.insert(pci_bus, 0xcf8, 0x8).unwrap();

        let pcie_cfg_mmio = Arc::new(Mutex::new(PciConfigMmio::new(pci.clone(), 12)));
        let pcie_cfg_mmio_len = pcie_cfg_mmio_range.len().unwrap();
        mmio_bus
            .insert(pcie_cfg_mmio, pcie_cfg_mmio_range.start, pcie_cfg_mmio_len)
            .unwrap();

        let pcie_vcfg_mmio = Arc::new(Mutex::new(PciVirtualConfigMmio::new(pci.clone(), 13)));
        mmio_bus
            .insert(
                pcie_vcfg_mmio,
                pcie_vcfg_range.start,
                pcie_vcfg_range.len().unwrap(),
            )
            .unwrap();

        // Event used to notify crosvm that guest OS is trying to suspend.
        let (suspend_tube_send, suspend_tube_recv) =
            Tube::directional_pair().map_err(Error::CreateTube)?;
        let suspend_tube_send = Arc::new(Mutex::new(suspend_tube_send));

        if components.fw_cfg_enable {
            Self::setup_fw_cfg_device(
                &io_bus,
                components.fw_cfg_parameters.clone(),
                components.bootorder_fw_cfg_blob.clone(),
                fw_cfg_jail,
                #[cfg(feature = "swap")]
                swap_controller,
            )?;
        }

        if !components.no_i8042 {
            Self::setup_legacy_i8042_device(
                &io_bus,
                irq_chip.pit_uses_speaker_port(),
                vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
            )?;
        }
        let mut vm_request_tube = if !components.no_rtc {
            let (host_tube, device_tube) = Tube::pair()
                .context("create tube")
                .map_err(Error::SetupCmos)?;
            Self::setup_legacy_cmos_device(
                arch_memory_layout,
                &io_bus,
                irq_chip,
                device_tube,
                components.memory_size,
            )
            .map_err(Error::SetupCmos)?;
            Some(host_tube)
        } else {
            None
        };
        let serial_devices = Self::setup_serial_devices(
            components.hv_cfg.protection_type,
            irq_chip.as_irq_chip_mut(),
            &io_bus,
            serial_parameters,
            serial_jail,
            #[cfg(feature = "swap")]
            swap_controller,
        )?;
        Self::setup_debugcon_devices(
            components.hv_cfg.protection_type,
            &io_bus,
            serial_parameters,
            debugcon_jail,
            #[cfg(feature = "swap")]
            swap_controller,
        )?;

        let bios_size = if let VmImage::Bios(ref bios) = components.vm_image {
            bios.metadata().map_err(Error::LoadBios)?.len()
        } else {
            0
        };
        if let Some(pflash_image) = components.pflash_image {
            Self::setup_pflash(
                pflash_image,
                components.pflash_block_size,
                bios_size,
                &mmio_bus,
                pflash_jail,
                #[cfg(feature = "swap")]
                swap_controller,
            )?;
        }

        // Functions that use/create jails MUST be used before the call to
        // setup_acpi_devices below, as this move us into a multiprocessing state
        // from which we can no longer fork.

        let mut resume_notify_devices = Vec::new();

        // each bus occupy 1MB mmio for pcie enhanced configuration
        let max_bus = (pcie_cfg_mmio_len / 0x100000 - 1) as u8;
        let (mut acpi_dev_resource, bat_control) = Self::setup_acpi_devices(
            arch_memory_layout,
            pci.clone(),
            &mem,
            &io_bus,
            system_allocator,
            suspend_tube_send.clone(),
            vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
            components.acpi_sdts,
            irq_chip.as_irq_chip_mut(),
            sci_irq,
            battery,
            &mmio_bus,
            max_bus,
            &mut resume_notify_devices,
            #[cfg(feature = "swap")]
            swap_controller,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            components.ac_adapter,
            guest_suspended_cvar,
            &pci_irqs,
        )?;

        // Create customized SSDT table
        let sdt = acpi::create_customize_ssdt(pci.clone(), amls, gpe_scope_amls);
        if let Some(sdt) = sdt {
            acpi_dev_resource.sdts.push(sdt);
        }

        irq_chip
            .finalize_devices(system_allocator, &io_bus, &mmio_bus)
            .map_err(Error::RegisterIrqfd)?;

        // All of these bios generated tables are set manually for the benefit of the kernel boot
        // flow (since there's no BIOS to set it) and for the BIOS boot flow since crosvm doesn't
        // have a way to pass the BIOS these configs.
        // This works right now because the only guest BIOS used with crosvm (u-boot) ignores these
        // tables and the guest OS picks them up.
        // If another guest does need a way to pass these tables down to it's BIOS, this approach
        // should be rethought.

        // Make sure the `vcpu_count` casts below and the arithmetic in `setup_mptable` are well
        // defined.
        if vcpu_count >= u8::MAX.into() {
            return Err(Error::TooManyVcpus);
        }

        if mptable {
            mptable::setup_mptable(&mem, vcpu_count as u8, &pci_irqs)
                .map_err(Error::SetupMptable)?;
        }
        smbios::setup_smbios(&mem, &components.smbios, bios_size).map_err(Error::SetupSmbios)?;

        let host_cpus = if components.host_cpu_topology {
            components.vcpu_affinity.clone()
        } else {
            None
        };

        // TODO (tjeznach) Write RSDP to bootconfig before writing to memory
        acpi::create_acpi_tables(
            &mem,
            vcpu_count as u8,
            sci_irq,
            0xcf9,
            6, // RST_CPU|SYS_RST
            &acpi_dev_resource,
            host_cpus,
            vcpu_ids,
            &pci_irqs,
            pcie_cfg_mmio_range.start,
            max_bus,
            components.force_s2idle,
        )
        .ok_or(Error::CreateAcpi)?;

        let mut cmdline = Self::get_base_linux_cmdline();

        get_serial_cmdline(&mut cmdline, serial_parameters, "io", &serial_devices)
            .map_err(Error::GetSerialCmdline)?;

        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        if let Some(ramoops_region) = ramoops_region {
            arch::pstore::add_ramoops_kernel_cmdline(&mut cmdline, &ramoops_region)
                .map_err(Error::Cmdline)?;
        }

        let pci_start = arch_memory_layout.pci_mmio_before_32bit.start;

        let mut vcpu_init = vec![VcpuInitX86_64::default(); vcpu_count];
        let mut msrs = BTreeMap::new();

        let protection_type = components.hv_cfg.protection_type;

        match components.vm_image {
            VmImage::Bios(ref mut bios) => {
                if protection_type.runs_firmware() {
                    return Err(Error::PvmFwBiosUnsupported);
                }

                // Allow a bios to hardcode CMDLINE_OFFSET and read the kernel command line from it.
                Self::load_cmdline(
                    &mem,
                    GuestAddress(CMDLINE_OFFSET),
                    cmdline,
                    CMDLINE_MAX_SIZE as usize - 1,
                )?;
                Self::load_bios(&mem, bios)?;
                regs::set_default_msrs(&mut msrs);
                // The default values for `Regs` and `Sregs` already set up the reset vector.
            }
            VmImage::Kernel(ref mut kernel_image) => {
                let (params, kernel_region, kernel_entry, mut cpu_mode, kernel_type) =
                    Self::load_kernel(&mem, kernel_image)?;

                info!("Loaded {} kernel", kernel_type);

                Self::setup_system_memory(
                    arch_memory_layout,
                    &mem,
                    cmdline,
                    components.initrd_image,
                    components.android_fstab,
                    kernel_region,
                    params,
                    dump_device_tree_blob,
                    device_tree_overlays,
                    protection_type,
                )?;

                if protection_type.needs_firmware_loaded() {
                    arch::load_image(
                        &mem,
                        &mut components
                            .pvm_fw
                            .expect("pvmfw must be available if ProtectionType loads it"),
                        GuestAddress(PROTECTED_VM_FW_START),
                        PROTECTED_VM_FW_MAX_SIZE,
                    )
                    .map_err(Error::LoadCustomPvmFw)?;
                } else if protection_type.runs_firmware() {
                    // Tell the hypervisor to load the pVM firmware.
                    vm.load_protected_vm_firmware(
                        GuestAddress(PROTECTED_VM_FW_START),
                        PROTECTED_VM_FW_MAX_SIZE,
                    )
                    .map_err(Error::LoadPvmFw)?;
                }

                let entry_addr = if protection_type.needs_firmware_loaded() {
                    Some(PROTECTED_VM_FW_START)
                } else if protection_type.runs_firmware() {
                    None // Initial RIP value is set by the hypervisor
                } else {
                    Some(kernel_entry.offset())
                };

                if let Some(entry) = entry_addr {
                    vcpu_init[0].regs.rip = entry;
                }

                match kernel_type {
                    KernelType::BzImage | KernelType::Elf => {
                        // Configure the bootstrap VCPU for the Linux/x86 boot protocol.
                        // <https://www.kernel.org/doc/html/latest/x86/boot.html>
                        vcpu_init[0].regs.rsp = BOOT_STACK_POINTER;
                        vcpu_init[0].regs.rsi = ZERO_PAGE_OFFSET;
                    }
                    KernelType::Multiboot => {
                        // Provide Multiboot-compatible bootloader information.
                        vcpu_init[0].regs.rax = MULTIBOOT_BOOTLOADER_MAGIC.into();
                        vcpu_init[0].regs.rbx = MULTIBOOT_INFO_OFFSET;
                    }
                }

                if protection_type.runs_firmware() {
                    // Pass DTB address to pVM firmware. This is redundant with the DTB entry in the
                    // `setup_data` list, but it allows the pVM firmware to know the location of the
                    // DTB without having the `setup_data` region mapped yet.
                    if let Some(fdt_setup_data_addr) = find_setup_data(
                        &mem,
                        GuestAddress(SETUP_DATA_START),
                        GuestAddress(SETUP_DATA_END),
                        SetupDataType::Dtb,
                    ) {
                        vcpu_init[0].regs.rdx =
                            fdt_setup_data_addr.offset() + size_of::<setup_data_hdr>() as u64;
                    }

                    // Pass pVM payload entry address to pVM firmware.
                    // NOTE: this is only for development purposes. An actual pvmfw
                    // implementation should not use this value and should instead receive
                    // the pVM payload start and size info from crosvm as the DTB properties
                    // /config/kernel-address and /config/kernel-size and determine the offset
                    // of the entry point on its own, not trust crosvm to provide it.
                    vcpu_init[0].regs.rdi = kernel_entry.offset();

                    // The pVM firmware itself always starts in 32-bit protected mode
                    // with paging disabled, regardless of the type of payload.
                    cpu_mode = CpuMode::FlatProtectedMode;
                }

                match cpu_mode {
                    CpuMode::LongMode => {
                        regs::set_long_mode_msrs(&mut msrs);

                        // Set up long mode and enable paging.
                        regs::configure_segments_and_sregs(&mem, &mut vcpu_init[0].sregs)
                            .map_err(Error::ConfigureSegments)?;
                        regs::setup_page_tables(&mem, &mut vcpu_init[0].sregs)
                            .map_err(Error::SetupPageTables)?;
                    }
                    CpuMode::FlatProtectedMode => {
                        regs::set_default_msrs(&mut msrs);

                        // Set up 32-bit protected mode with paging disabled.
                        regs::configure_segments_and_sregs_flat32(&mem, &mut vcpu_init[0].sregs)
                            .map_err(Error::ConfigureSegments)?;
                    }
                }

                regs::set_mtrr_msrs(&mut msrs, &vm, pci_start);
            }
        }

        // Initialize MSRs for all VCPUs.
        for vcpu in vcpu_init.iter_mut() {
            vcpu.msrs = msrs.clone();
        }

        let mut vm_request_tubes = Vec::new();
        if let Some(req_tube) = vm_request_tube.take() {
            vm_request_tubes.push(req_tube);
        }

        Ok(RunnableLinuxVm {
            vm,
            vcpu_count,
            vcpus: None,
            vcpu_affinity: components.vcpu_affinity,
            vcpu_init,
            no_smt: components.no_smt,
            irq_chip: irq_chip.try_box_clone().map_err(Error::CloneIrqChip)?,
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            suspend_tube: (suspend_tube_send, suspend_tube_recv),
            resume_notify_devices,
            rt_cpus: components.rt_cpus,
            delay_rt: components.delay_rt,
            bat_control,
            pm: Some(acpi_dev_resource.pm),
            root_config: pci,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            platform_devices: Vec::new(),
            hotplug_bus: BTreeMap::new(),
            devices_thread: None,
            vm_request_tubes,
        })
    }

    fn configure_vcpu<V: Vm>(
        vm: &V,
        hypervisor: &dyn HypervisorX86_64,
        irq_chip: &mut dyn IrqChipX86_64,
        vcpu: &mut dyn VcpuX86_64,
        vcpu_init: VcpuInitX86_64,
        vcpu_id: usize,
        num_cpus: usize,
        cpu_config: Option<CpuConfigX86_64>,
    ) -> Result<()> {
        let cpu_config = match cpu_config {
            Some(config) => config,
            None => return Err(Error::InvalidCpuConfig),
        };
        if !vm.check_capability(VmCap::EarlyInitCpuid) {
            cpuid::setup_cpuid(hypervisor, irq_chip, vcpu, vcpu_id, num_cpus, cpu_config)
                .map_err(Error::SetupCpuid)?;
        }

        vcpu.set_regs(&vcpu_init.regs).map_err(Error::WriteRegs)?;

        vcpu.set_sregs(&vcpu_init.sregs)
            .map_err(Error::SetupSregs)?;

        vcpu.set_fpu(&vcpu_init.fpu).map_err(Error::SetupFpu)?;

        let vcpu_supported_var_mtrrs = regs::vcpu_supported_variable_mtrrs(vcpu);
        let num_var_mtrrs = regs::count_variable_mtrrs(&vcpu_init.msrs);
        let skip_mtrr_msrs = if num_var_mtrrs > vcpu_supported_var_mtrrs {
            warn!(
                "Too many variable MTRR entries ({} required, {} supported),
                please check pci_start addr, guest with pass through device may be very slow",
                num_var_mtrrs, vcpu_supported_var_mtrrs,
            );
            // Filter out the MTRR entries from the MSR list.
            true
        } else {
            false
        };

        for (msr_index, value) in vcpu_init.msrs.into_iter() {
            if skip_mtrr_msrs && regs::is_mtrr_msr(msr_index) {
                continue;
            }

            vcpu.set_msr(msr_index, value).map_err(Error::SetupMsrs)?;
        }

        interrupts::set_lint(vcpu_id, irq_chip).map_err(Error::SetLint)?;

        Ok(())
    }

    fn register_pci_device<V: VmX86_64, Vcpu: VcpuX86_64>(
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        device: Box<dyn PciDevice>,
        #[cfg(any(target_os = "android", target_os = "linux"))] minijail: Option<Minijail>,
        resources: &mut SystemAllocator,
        hp_control_tube: &mpsc::Sender<PciRootCommand>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<PciAddress> {
        arch::configure_pci_device(
            linux,
            device,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            minijail,
            resources,
            hp_control_tube,
            #[cfg(feature = "swap")]
            swap_controller,
        )
        .map_err(Error::ConfigurePciDevice)
    }

    fn get_host_cpu_frequencies_khz() -> Result<BTreeMap<usize, Vec<u32>>> {
        Ok(BTreeMap::new())
    }

    fn get_host_cpu_max_freq_khz() -> Result<BTreeMap<usize, u32>> {
        Ok(BTreeMap::new())
    }

    fn get_host_cpu_capacity() -> Result<BTreeMap<usize, u32>> {
        Ok(BTreeMap::new())
    }

    fn get_host_cpu_clusters() -> Result<Vec<CpuSet>> {
        Ok(Vec::new())
    }
}

// OSC returned status register in CDW1
const OSC_STATUS_UNSUPPORT_UUID: u32 = 0x4;
// pci host bridge OSC returned control register in CDW3
#[allow(dead_code)]
const PCI_HB_OSC_CONTROL_PCIE_HP: u32 = 0x1;
const PCI_HB_OSC_CONTROL_SHPC_HP: u32 = 0x2;
#[allow(dead_code)]
const PCI_HB_OSC_CONTROL_PCIE_PME: u32 = 0x4;
const PCI_HB_OSC_CONTROL_PCIE_AER: u32 = 0x8;
#[allow(dead_code)]
const PCI_HB_OSC_CONTROL_PCIE_CAP: u32 = 0x10;

struct PciRootOSC {}

// Method (_OSC, 4, NotSerialized)  // _OSC: Operating System Capabilities
// {
//     CreateDWordField (Arg3, Zero, CDW1)  // flag and return value
//     If (Arg0 == ToUUID ("33db4d5b-1ff7-401c-9657-7441c03dd766"))
//     {
//         CreateDWordField (Arg3, 8, CDW3) // control field
//         if ( 0 == (CDW1 & 0x01))  // Query flag ?
//         {
//              CDW3 &= !(SHPC_HP | AER)
//         }
//     } Else {
//         CDW1 |= UNSUPPORT_UUID
//     }
//     Return (Arg3)
// }
impl Aml for PciRootOSC {
    fn to_aml_bytes(&self, aml: &mut Vec<u8>) {
        let osc_uuid = "33DB4D5B-1FF7-401C-9657-7441C03DD766";
        // virtual pcie root port supports hotplug, pme, and pcie cap register, clear all
        // the other bits.
        let mask = !(PCI_HB_OSC_CONTROL_SHPC_HP | PCI_HB_OSC_CONTROL_PCIE_AER);
        aml::Method::new(
            "_OSC".into(),
            4,
            false,
            vec![
                &aml::CreateDWordField::new(
                    &aml::Name::new_field_name("CDW1"),
                    &aml::Arg(3),
                    &aml::ZERO,
                ),
                &aml::If::new(
                    &aml::Equal::new(&aml::Arg(0), &aml::Uuid::new(osc_uuid)),
                    vec![
                        &aml::CreateDWordField::new(
                            &aml::Name::new_field_name("CDW3"),
                            &aml::Arg(3),
                            &(8_u8),
                        ),
                        &aml::If::new(
                            &aml::Equal::new(
                                &aml::ZERO,
                                &aml::And::new(
                                    &aml::ZERO,
                                    &aml::Name::new_field_name("CDW1"),
                                    &aml::ONE,
                                ),
                            ),
                            vec![&aml::And::new(
                                &aml::Name::new_field_name("CDW3"),
                                &mask,
                                &aml::Name::new_field_name("CDW3"),
                            )],
                        ),
                    ],
                ),
                &aml::Else::new(vec![&aml::Or::new(
                    &aml::Name::new_field_name("CDW1"),
                    &OSC_STATUS_UNSUPPORT_UUID,
                    &aml::Name::new_field_name("CDW1"),
                )]),
                &aml::Return::new(&aml::Arg(3)),
            ],
        )
        .to_aml_bytes(aml)
    }
}

pub enum CpuMode {
    /// 32-bit protected mode with paging disabled.
    FlatProtectedMode,

    /// 64-bit long mode.
    LongMode,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KernelType {
    BzImage,
    Elf,
    Multiboot,
}

impl fmt::Display for KernelType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KernelType::BzImage => write!(f, "bzImage"),
            KernelType::Elf => write!(f, "ELF"),
            KernelType::Multiboot => write!(f, "Multiboot"),
        }
    }
}

impl X8664arch {
    /// Loads the bios from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `bios_image` - the File object for the specified bios
    fn load_bios(mem: &GuestMemory, bios_image: &mut File) -> Result<()> {
        let bios_image_length = bios_image.get_len().map_err(Error::LoadBios)?;
        if bios_image_length >= FIRST_ADDR_PAST_32BITS {
            return Err(Error::LoadBios(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bios was {} bytes, expected less than {}",
                    bios_image_length, FIRST_ADDR_PAST_32BITS,
                ),
            )));
        }

        let guest_slice = mem
            .get_slice_at_addr(bios_start(bios_image_length), bios_image_length as usize)
            .map_err(Error::SetupGuestMemory)?;
        bios_image
            .read_exact_at_volatile(guest_slice, 0)
            .map_err(Error::LoadBios)?;
        Ok(())
    }

    fn setup_pflash(
        pflash_image: File,
        block_size: u32,
        bios_size: u64,
        mmio_bus: &Bus,
        jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<()> {
        let size = pflash_image.metadata().map_err(Error::LoadPflash)?.len();
        let start = FIRST_ADDR_PAST_32BITS - bios_size - size;
        let pflash_image = Box::new(pflash_image);

        #[cfg(any(target_os = "android", target_os = "linux"))]
        let fds = pflash_image.as_raw_descriptors();

        let pflash = Pflash::new(pflash_image, block_size).map_err(Error::SetupPflash)?;
        let pflash: Arc<Mutex<dyn BusDevice>> = match jail {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Some(jail) => Arc::new(Mutex::new(
                ProxyDevice::new(
                    pflash,
                    jail,
                    fds,
                    #[cfg(feature = "swap")]
                    swap_controller,
                )
                .map_err(Error::CreateProxyDevice)?,
            )),
            #[cfg(windows)]
            Some(_) => unreachable!(),
            None => Arc::new(Mutex::new(pflash)),
        };
        mmio_bus
            .insert(pflash, start, size)
            .map_err(Error::InsertBus)?;

        Ok(())
    }

    /// Writes the command line string to the given memory slice.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
    /// * `guest_addr` - The address in `guest_mem` at which to load the command line.
    /// * `cmdline` - The kernel command line.
    /// * `kernel_max_cmdline_len` - The maximum command line length (without NUL terminator)
    ///   supported by the kernel.
    fn load_cmdline(
        guest_mem: &GuestMemory,
        guest_addr: GuestAddress,
        cmdline: kernel_cmdline::Cmdline,
        kernel_max_cmdline_len: usize,
    ) -> Result<()> {
        let mut cmdline_guest_mem_slice = guest_mem
            .get_slice_at_addr(guest_addr, CMDLINE_MAX_SIZE as usize)
            .map_err(|_| Error::CommandLineOverflow)?;

        let mut cmdline_bytes: Vec<u8> = cmdline
            .into_bytes_with_max_len(kernel_max_cmdline_len)
            .map_err(Error::Cmdline)?;
        cmdline_bytes.push(0u8); // Add NUL terminator.

        cmdline_guest_mem_slice
            .write_all(&cmdline_bytes)
            .map_err(|_| Error::CommandLineOverflow)?;

        Ok(())
    }

    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    ///
    /// # Returns
    ///
    /// On success, returns the Linux x86_64 boot protocol parameters, the address range containing
    /// the kernel, the entry point (initial `RIP` value), the initial CPU mode, and the type of
    /// kernel.
    fn load_kernel(
        mem: &GuestMemory,
        kernel_image: &mut File,
    ) -> Result<(boot_params, AddressRange, GuestAddress, CpuMode, KernelType)> {
        let kernel_start = GuestAddress(KERNEL_START_OFFSET);

        let multiboot =
            kernel_loader::multiboot_header_from_file(kernel_image).map_err(Error::LoadKernel)?;

        if let Some(multiboot_load) = multiboot.as_ref().and_then(|m| m.load.as_ref()) {
            let loaded_kernel = kernel_loader::load_multiboot(mem, kernel_image, multiboot_load)
                .map_err(Error::LoadKernel)?;

            let boot_params = boot_params {
                hdr: setup_header {
                    cmdline_size: CMDLINE_MAX_SIZE as u32 - 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            return Ok((
                boot_params,
                loaded_kernel.address_range,
                loaded_kernel.entry,
                CpuMode::FlatProtectedMode,
                KernelType::Multiboot,
            ));
        }

        match kernel_loader::load_elf(mem, kernel_start, kernel_image, 0) {
            Ok(loaded_kernel) => {
                // ELF kernels don't contain a `boot_params` structure, so synthesize a default one.
                let boot_params = boot_params {
                    hdr: setup_header {
                        cmdline_size: CMDLINE_MAX_SIZE as u32 - 1,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                Ok((
                    boot_params,
                    loaded_kernel.address_range,
                    loaded_kernel.entry,
                    match loaded_kernel.class {
                        kernel_loader::ElfClass::ElfClass32 => CpuMode::FlatProtectedMode,
                        kernel_loader::ElfClass::ElfClass64 => CpuMode::LongMode,
                    },
                    KernelType::Elf,
                ))
            }
            Err(kernel_loader::Error::InvalidMagicNumber) => {
                // The image failed to parse as ELF, so try to load it as a bzImage.
                let (boot_params, bzimage_region, bzimage_entry, cpu_mode) =
                    bzimage::load_bzimage(mem, kernel_start, kernel_image)
                        .map_err(Error::LoadBzImage)?;
                Ok((
                    boot_params,
                    bzimage_region,
                    bzimage_entry,
                    cpu_mode,
                    KernelType::BzImage,
                ))
            }
            Err(e) => Err(Error::LoadKernel(e)),
        }
    }

    /// Configures the system memory space should be called once per vm before
    /// starting vcpu threads.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `cmdline` - the kernel commandline
    /// * `initrd_file` - an initial ramdisk image
    pub fn setup_system_memory(
        arch_memory_layout: &ArchMemoryLayout,
        mem: &GuestMemory,
        cmdline: kernel_cmdline::Cmdline,
        initrd_file: Option<File>,
        android_fstab: Option<File>,
        kernel_region: AddressRange,
        params: boot_params,
        dump_device_tree_blob: Option<PathBuf>,
        device_tree_overlays: Vec<DtbOverlay>,
        protection_type: ProtectionType,
    ) -> Result<()> {
        let e820_entries = generate_e820_memory_map(arch_memory_layout, mem)?;

        let kernel_max_cmdline_len = if params.hdr.cmdline_size == 0 {
            // Old kernels have a maximum length of 255 bytes, not including the NUL.
            255
        } else {
            params.hdr.cmdline_size as usize
        };
        debug!("kernel_max_cmdline_len={kernel_max_cmdline_len}");
        Self::load_cmdline(
            mem,
            GuestAddress(CMDLINE_OFFSET),
            cmdline,
            kernel_max_cmdline_len,
        )?;

        let initrd = match initrd_file {
            Some(mut initrd_file) => {
                let initrd_addr_max = if params.hdr.xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G != 0 {
                    u64::MAX
                } else if params.hdr.initrd_addr_max == 0 {
                    // Default initrd_addr_max for old kernels (see Documentation/x86/boot.txt).
                    0x37FFFFFF
                } else {
                    u64::from(params.hdr.initrd_addr_max)
                };

                let (initrd_start, initrd_size) = arch::load_image_high(
                    mem,
                    &mut initrd_file,
                    GuestAddress(kernel_region.end + 1),
                    GuestAddress(initrd_addr_max),
                    Some(|region| {
                        region.options.purpose != MemoryRegionPurpose::ProtectedFirmwareRegion
                    }),
                    base::pagesize() as u64,
                )
                .map_err(Error::LoadInitrd)?;
                Some((initrd_start, initrd_size))
            }
            None => None,
        };

        let mut setup_data_entries =
            SetupDataEntries::new(SETUP_DATA_START as usize, SETUP_DATA_END as usize);

        let setup_data_size = setup_data_entries.insert(setup_data_rng_seed());

        // SETUP_DTB should be the last one in SETUP_DATA.
        // This is to reserve enough space for SETUP_DTB
        // without exceeding the size of SETUP_DATA area.
        if android_fstab.is_some()
            || !device_tree_overlays.is_empty()
            || protection_type.runs_firmware()
        {
            let fdt_max_size = min(X86_64_FDT_MAX_SIZE as usize, setup_data_size);
            let mut device_tree_blob = fdt::create_fdt(
                mem,
                android_fstab,
                dump_device_tree_blob,
                device_tree_overlays,
                kernel_region,
                initrd,
            )
            .map_err(Error::CreateFdt)?;
            if device_tree_blob.len() > fdt_max_size {
                return Err(Error::DTBSizeGreaterThanAllowed);
            }

            // Reserve and zero fill dtb memory to maximum allowable size
            // so that pvmfw could patch and extend the dtb in-place.
            device_tree_blob.resize(fdt_max_size, 0);

            setup_data_entries.insert(SetupData {
                data: device_tree_blob,
                type_: SetupDataType::Dtb,
            });
        }

        let setup_data = setup_data_entries.write_setup_data(mem)?;

        configure_boot_params(
            mem,
            GuestAddress(CMDLINE_OFFSET),
            setup_data,
            initrd,
            params,
            &e820_entries,
        )?;

        configure_multiboot_info(mem, GuestAddress(CMDLINE_OFFSET), &e820_entries)?;

        Ok(())
    }

    fn get_pcie_vcfg_mmio_range(mem: &GuestMemory, pcie_cfg_mmio: &AddressRange) -> AddressRange {
        // Put PCIe VCFG region at a 2MB boundary after physical memory or 4gb, whichever is
        // greater.
        let ram_end_round_2mb = mem.end_addr().offset().next_multiple_of(2 * MB);
        let start = std::cmp::max(ram_end_round_2mb, 4 * GB);
        // Each pci device's ECAM size is 4kb and its vcfg size is 8kb
        let end = start + pcie_cfg_mmio.len().unwrap() * 2 - 1;
        AddressRange { start, end }
    }

    /// Returns the high mmio range
    fn get_high_mmio_range<V: Vm>(vm: &V, arch_memory_layout: &ArchMemoryLayout) -> AddressRange {
        let mem = vm.get_memory();
        let start = Self::get_pcie_vcfg_mmio_range(mem, &arch_memory_layout.pcie_cfg_mmio).end + 1;

        let phys_mem_end = (1u64 << vm.get_guest_phys_addr_bits()) - 1;
        let high_mmio_end = std::cmp::min(phys_mem_end, HIGH_MMIO_MAX_END);

        AddressRange {
            start,
            end: high_mmio_end,
        }
    }

    /// This returns a minimal kernel command for this architecture
    pub fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new();
        cmdline.insert_str("panic=-1").unwrap();

        cmdline
    }

    /// Sets up fw_cfg device.
    ///  # Arguments
    ///
    /// * `io_bus` - the IO bus object
    /// * `fw_cfg_parameters` - command-line specified data to add to device. May contain all None
    ///   fields if user did not specify data to add to the device
    fn setup_fw_cfg_device(
        io_bus: &Bus,
        fw_cfg_parameters: Vec<FwCfgParameters>,
        bootorder_fw_cfg_blob: Vec<u8>,
        fw_cfg_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<()> {
        let fw_cfg = match devices::FwCfgDevice::new(FW_CFG_MAX_FILE_SLOTS, fw_cfg_parameters) {
            Ok(mut device) => {
                // this condition will only be true if the user specified at least one bootindex
                // option on the command line. If none were specified, bootorder_fw_cfg_blob will
                // only have a null byte (null terminator)
                if bootorder_fw_cfg_blob.len() > 1 {
                    // Add boot order file to the device. If the file is not present, firmware may
                    // not be able to boot.
                    if let Err(err) = device.add_file(
                        "bootorder",
                        bootorder_fw_cfg_blob,
                        devices::FwCfgItemType::GenericItem,
                    ) {
                        return Err(Error::CreateFwCfgDevice(err));
                    }
                }
                device
            }
            Err(err) => {
                return Err(Error::CreateFwCfgDevice(err));
            }
        };

        let fw_cfg: Arc<Mutex<dyn BusDevice>> = match fw_cfg_jail.as_ref() {
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Some(jail) => {
                let jail_clone = jail.try_clone().map_err(Error::CloneJail)?;
                #[cfg(feature = "seccomp_trace")]
                debug!(
                    "seccomp_trace {{\"event\": \"minijail_clone\", \"src_jail_addr\": \"0x{:x}\", \"dst_jail_addr\": \"0x{:x}\"}}",
                    read_jail_addr(jail),
                    read_jail_addr(&jail_clone)
                );
                Arc::new(Mutex::new(
                    ProxyDevice::new(
                        fw_cfg,
                        jail_clone,
                        Vec::new(),
                        #[cfg(feature = "swap")]
                        swap_controller,
                    )
                    .map_err(Error::CreateProxyDevice)?,
                ))
            }
            #[cfg(windows)]
            Some(_) => unreachable!(),
            None => Arc::new(Mutex::new(fw_cfg)),
        };

        io_bus
            .insert(fw_cfg, FW_CFG_BASE_PORT, FW_CFG_WIDTH)
            .map_err(Error::InsertBus)?;

        Ok(())
    }

    /// Sets up the legacy x86 i8042/KBD platform device
    ///
    /// # Arguments
    ///
    /// * - `io_bus` - the IO bus object
    /// * - `pit_uses_speaker_port` - does the PIT use port 0x61 for the PC speaker
    /// * - `vm_evt_wrtube` - the event object which should receive exit events
    pub fn setup_legacy_i8042_device(
        io_bus: &Bus,
        pit_uses_speaker_port: bool,
        vm_evt_wrtube: SendTube,
    ) -> Result<()> {
        let i8042 = Arc::new(Mutex::new(devices::I8042Device::new(
            vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
        )));

        if pit_uses_speaker_port {
            io_bus.insert(i8042, 0x062, 0x3).unwrap();
        } else {
            io_bus.insert(i8042, 0x061, 0x4).unwrap();
        }

        Ok(())
    }

    /// Sets up the legacy x86 CMOS/RTC platform device
    /// # Arguments
    ///
    /// * - `io_bus` - the IO bus object
    /// * - `mem_size` - the size in bytes of physical ram for the guest
    pub fn setup_legacy_cmos_device(
        arch_memory_layout: &ArchMemoryLayout,
        io_bus: &Bus,
        irq_chip: &mut dyn IrqChipX86_64,
        vm_control: Tube,
        mem_size: u64,
    ) -> anyhow::Result<()> {
        let mem_regions = arch_memory_regions(arch_memory_layout, mem_size, None);

        let mem_below_4g = mem_regions
            .iter()
            .filter(|r| r.0.offset() < FIRST_ADDR_PAST_32BITS)
            .map(|r| r.1)
            .sum();

        let mem_above_4g = mem_regions
            .iter()
            .filter(|r| r.0.offset() >= FIRST_ADDR_PAST_32BITS)
            .map(|r| r.1)
            .sum();

        let irq_evt = devices::IrqEdgeEvent::new().context("cmos irq")?;
        let cmos = devices::cmos::Cmos::new(
            mem_below_4g,
            mem_above_4g,
            Utc::now,
            vm_control,
            irq_evt.try_clone().context("cmos irq clone")?,
        )
        .context("create cmos")?;

        irq_chip
            .register_edge_irq_event(
                devices::cmos::RTC_IRQ as u32,
                &irq_evt,
                IrqEventSource::from_device(&cmos),
            )
            .context("cmos register irq")?;
        io_bus
            .insert(Arc::new(Mutex::new(cmos)), 0x70, 0x2)
            .context("cmos insert irq")?;

        Ok(())
    }

    /// Sets up the acpi devices for this platform and
    /// return the resources which is used to set the ACPI tables.
    ///
    /// # Arguments
    ///
    /// * `io_bus` the I/O bus to add the devices to
    /// * `resources` the SystemAllocator to allocate IO and MMIO for acpi devices.
    /// * `suspend_tube` the tube object which used to suspend/resume the VM.
    /// * `sdts` ACPI system description tables
    /// * `irq_chip` the IrqChip object for registering irq events
    /// * `battery` indicate whether to create the battery
    /// * `mmio_bus` the MMIO bus to add the devices to
    /// * `pci_irqs` IRQ assignment of PCI devices. Tuples of (PCI address, gsi, PCI interrupt pin).
    ///   Note that this matches one of the return values of generate_pci_root.
    pub fn setup_acpi_devices(
        arch_memory_layout: &ArchMemoryLayout,
        pci_root: Arc<Mutex<PciRoot>>,
        mem: &GuestMemory,
        io_bus: &Bus,
        resources: &mut SystemAllocator,
        suspend_tube: Arc<Mutex<SendTube>>,
        vm_evt_wrtube: SendTube,
        sdts: Vec<SDT>,
        irq_chip: &mut dyn IrqChip,
        sci_irq: u32,
        battery: (Option<BatteryType>, Option<Minijail>),
        #[cfg_attr(windows, allow(unused_variables))] mmio_bus: &Bus,
        max_bus: u8,
        resume_notify_devices: &mut Vec<Arc<Mutex<dyn BusResumeDevice>>>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        #[cfg(any(target_os = "android", target_os = "linux"))] ac_adapter: bool,
        guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
        pci_irqs: &[(PciAddress, u32, PciInterruptPin)],
    ) -> Result<(acpi::AcpiDevResource, Option<BatControl>)> {
        // The AML data for the acpi devices
        let mut amls = Vec::new();

        let bat_control = if let Some(battery_type) = battery.0 {
            match battery_type {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                BatteryType::Goldfish => {
                    let irq_num = resources.allocate_irq().ok_or(Error::CreateBatDevices(
                        arch::DeviceRegistrationError::AllocateIrq,
                    ))?;
                    let (control_tube, _mmio_base) = arch::sys::linux::add_goldfish_battery(
                        &mut amls,
                        battery.1,
                        mmio_bus,
                        irq_chip,
                        irq_num,
                        resources,
                        #[cfg(feature = "swap")]
                        swap_controller,
                    )
                    .map_err(Error::CreateBatDevices)?;
                    Some(BatControl {
                        type_: BatteryType::Goldfish,
                        control_tube,
                    })
                }
                #[cfg(windows)]
                _ => None,
            }
        } else {
            None
        };

        let pm_alloc = resources.get_anon_alloc();
        let pm_iobase = match resources.io_allocator() {
            Some(io) => io
                .allocate_with_align(
                    devices::acpi::ACPIPM_RESOURCE_LEN as u64,
                    pm_alloc,
                    "ACPIPM".to_string(),
                    4, // must be 32-bit aligned
                )
                .map_err(Error::AllocateIOResouce)?,
            None => 0x600,
        };

        let pcie_vcfg = aml::Name::new(
            "VCFG".into(),
            &Self::get_pcie_vcfg_mmio_range(mem, &arch_memory_layout.pcie_cfg_mmio).start,
        );
        pcie_vcfg.to_aml_bytes(&mut amls);

        let pm_sci_evt = devices::IrqLevelEvent::new().map_err(Error::CreateEvent)?;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        let acdc = if ac_adapter {
            // Allocate GPE for AC adapter notfication
            let gpe = resources.allocate_gpe().ok_or(Error::AllocateGpe)?;

            let alloc = resources.get_anon_alloc();
            let mmio_base = resources
                .allocate_mmio(
                    devices::ac_adapter::ACDC_VIRT_MMIO_SIZE,
                    alloc,
                    "AcAdapter".to_string(),
                    resources::AllocOptions::new().align(devices::ac_adapter::ACDC_VIRT_MMIO_SIZE),
                )
                .unwrap();
            let ac_adapter_dev = devices::ac_adapter::AcAdapter::new(mmio_base, gpe);
            let ac_dev = Arc::new(Mutex::new(ac_adapter_dev));
            mmio_bus
                .insert(
                    ac_dev.clone(),
                    mmio_base,
                    devices::ac_adapter::ACDC_VIRT_MMIO_SIZE,
                )
                .unwrap();

            ac_dev.lock().to_aml_bytes(&mut amls);
            Some(ac_dev)
        } else {
            None
        };
        #[cfg(windows)]
        let acdc = None;

        //Virtual PMC
        if let Some(guest_suspended_cvar) = guest_suspended_cvar {
            let alloc = resources.get_anon_alloc();
            let mmio_base = resources
                .allocate_mmio(
                    devices::pmc_virt::VPMC_VIRT_MMIO_SIZE,
                    alloc,
                    "VirtualPmc".to_string(),
                    resources::AllocOptions::new().align(devices::pmc_virt::VPMC_VIRT_MMIO_SIZE),
                )
                .unwrap();

            let pmc_virtio_mmio =
                Arc::new(Mutex::new(VirtualPmc::new(mmio_base, guest_suspended_cvar)));
            mmio_bus
                .insert(
                    pmc_virtio_mmio.clone(),
                    mmio_base,
                    devices::pmc_virt::VPMC_VIRT_MMIO_SIZE,
                )
                .unwrap();
            pmc_virtio_mmio.lock().to_aml_bytes(&mut amls);
        }

        let mut pmresource = devices::ACPIPMResource::new(
            pm_sci_evt.try_clone().map_err(Error::CloneEvent)?,
            suspend_tube,
            vm_evt_wrtube,
            acdc,
        );
        pmresource.to_aml_bytes(&mut amls);
        irq_chip
            .register_level_irq_event(
                sci_irq,
                &pm_sci_evt,
                IrqEventSource::from_device(&pmresource),
            )
            .map_err(Error::RegisterIrqfd)?;
        pmresource.start();

        let mut crs_entries: Vec<Box<dyn Aml>> = vec![
            Box::new(aml::AddressSpace::new_bus_number(0x0u16, max_bus as u16)),
            Box::new(aml::IO::new(0xcf8, 0xcf8, 1, 0x8)),
        ];
        for r in resources.mmio_pools() {
            let entry: Box<dyn Aml> = match (u32::try_from(r.start), u32::try_from(r.end)) {
                (Ok(start), Ok(end)) => Box::new(aml::AddressSpace::new_memory(
                    aml::AddressSpaceCachable::NotCacheable,
                    true,
                    start,
                    end,
                )),
                _ => Box::new(aml::AddressSpace::new_memory(
                    aml::AddressSpaceCachable::NotCacheable,
                    true,
                    r.start,
                    r.end,
                )),
            };
            crs_entries.push(entry);
        }

        let prt_entries: Vec<aml::Package> = pci_irqs
            .iter()
            .map(|(pci_address, gsi, pci_intr_pin)| {
                aml::Package::new(vec![
                    &pci_address.acpi_adr(),
                    &pci_intr_pin.to_mask(),
                    &aml::ZERO,
                    gsi,
                ])
            })
            .collect();

        aml::Device::new(
            "_SB_.PC00".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A08")),
                &aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A03")),
                &aml::Name::new("_ADR".into(), &aml::ZERO),
                &aml::Name::new("_SEG".into(), &aml::ZERO),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new("SUPP".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(crs_entries.iter().map(|b| b.as_ref()).collect()),
                ),
                &PciRootOSC {},
                &aml::Name::new(
                    "_PRT".into(),
                    &aml::Package::new(prt_entries.iter().map(|p| p as &dyn Aml).collect()),
                ),
            ],
        )
        .to_aml_bytes(&mut amls);

        if let (Some(start), Some(len)) = (
            u32::try_from(arch_memory_layout.pcie_cfg_mmio.start).ok(),
            arch_memory_layout
                .pcie_cfg_mmio
                .len()
                .and_then(|l| u32::try_from(l).ok()),
        ) {
            aml::Device::new(
                "_SB_.MB00".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C02")),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::Memory32Fixed::new(
                            true, start, len,
                        )]),
                    ),
                ],
            )
            .to_aml_bytes(&mut amls);
        } else {
            warn!("Failed to create ACPI MMCFG region reservation");
        }

        let root_bus = pci_root.lock().get_root_bus();
        let addresses = root_bus.lock().get_downstream_devices();
        for address in addresses {
            if let Some(acpi_path) = pci_root.lock().acpi_path(&address) {
                const DEEPEST_SLEEP_STATE: u32 = 3;
                aml::Device::new(
                    (*acpi_path).into(),
                    vec![
                        &aml::Name::new("_ADR".into(), &address.acpi_adr()),
                        &aml::Name::new(
                            "_PRW".into(),
                            &aml::Package::new(vec![&PM_WAKEUP_GPIO, &DEEPEST_SLEEP_STATE]),
                        ),
                    ],
                )
                .to_aml_bytes(&mut amls);
            }
        }

        let pm = Arc::new(Mutex::new(pmresource));
        io_bus
            .insert(
                pm.clone(),
                pm_iobase,
                devices::acpi::ACPIPM_RESOURCE_LEN as u64,
            )
            .unwrap();
        resume_notify_devices.push(pm.clone());

        Ok((
            acpi::AcpiDevResource {
                amls,
                pm_iobase,
                pm,
                sdts,
            },
            bat_control,
        ))
    }

    /// Sets up the serial devices for this platform. Returns a list of configured serial devices.
    ///
    /// # Arguments
    ///
    /// * - `irq_chip` the IrqChip object for registering irq events
    /// * - `io_bus` the I/O bus to add the devices to
    /// * - `serial_parameters` - definitions for how the serial devices should be configured
    pub fn setup_serial_devices(
        protection_type: ProtectionType,
        irq_chip: &mut dyn IrqChip,
        io_bus: &Bus,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<Vec<SerialDeviceInfo>> {
        let com_evt_1_3 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;

        let serial_devices = arch::add_serial_devices(
            protection_type,
            io_bus,
            (X86_64_SERIAL_1_3_IRQ, com_evt_1_3.get_trigger()),
            (X86_64_SERIAL_2_4_IRQ, com_evt_2_4.get_trigger()),
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
            .register_edge_irq_event(X86_64_SERIAL_1_3_IRQ, &com_evt_1_3, source.clone())
            .map_err(Error::RegisterIrqfd)?;
        irq_chip
            .register_edge_irq_event(X86_64_SERIAL_2_4_IRQ, &com_evt_2_4, source)
            .map_err(Error::RegisterIrqfd)?;

        Ok(serial_devices)
    }

    fn setup_debugcon_devices(
        protection_type: ProtectionType,
        io_bus: &Bus,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        debugcon_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<()> {
        for param in serial_parameters.values() {
            if param.hardware != SerialHardware::Debugcon {
                continue;
            }

            let mut preserved_fds = Vec::new();
            let con = param
                .create_serial_device::<Debugcon>(
                    protection_type,
                    // Debugcon doesn't use the interrupt event
                    &Event::new().map_err(Error::CreateEvent)?,
                    &mut preserved_fds,
                )
                .map_err(Error::CreateDebugconDevice)?;

            let con: Arc<Mutex<dyn BusDevice>> = match debugcon_jail.as_ref() {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                Some(jail) => {
                    let jail_clone = jail.try_clone().map_err(Error::CloneJail)?;
                    #[cfg(feature = "seccomp_trace")]
                    debug!(
                        "seccomp_trace {{\"event\": \"minijail_clone\", \"src_jail_addr\": \"0x{:x}\", \"dst_jail_addr\": \"0x{:x}\"}}",
                        read_jail_addr(jail),
                        read_jail_addr(&jail_clone)
                    );
                    Arc::new(Mutex::new(
                        ProxyDevice::new(
                            con,
                            jail_clone,
                            preserved_fds,
                            #[cfg(feature = "swap")]
                            swap_controller,
                        )
                        .map_err(Error::CreateProxyDevice)?,
                    ))
                }
                #[cfg(windows)]
                Some(_) => unreachable!(),
                None => Arc::new(Mutex::new(con)),
            };
            io_bus
                .insert(con.clone(), param.debugcon_port.into(), 1)
                .map_err(Error::InsertBus)?;
        }

        Ok(())
    }
}

#[sorted]
#[derive(Error, Debug)]
pub enum MsrError {
    #[error("CPU not support. Only intel CPUs support ITMT.")]
    CpuUnSupport,
    #[error("msr must be unique: {0}")]
    MsrDuplicate(u32),
}

#[derive(Error, Debug)]
pub enum HybridSupportError {
    #[error("Host CPU doesn't support hybrid architecture.")]
    UnsupportedHostCpu,
}

/// The wrapper for CPUID call functions.
pub struct CpuIdCall {
    /// __cpuid_count or a fake function for test.
    cpuid_count: unsafe fn(u32, u32) -> CpuidResult,
    /// __cpuid or a fake function for test.
    cpuid: unsafe fn(u32) -> CpuidResult,
}

impl CpuIdCall {
    pub fn new(
        cpuid_count: unsafe fn(u32, u32) -> CpuidResult,
        cpuid: unsafe fn(u32) -> CpuidResult,
    ) -> CpuIdCall {
        CpuIdCall { cpuid_count, cpuid }
    }
}

/// Check if host supports hybrid CPU feature. The check include:
///     1. Check if CPUID.1AH exists. CPUID.1AH is hybrid information enumeration leaf.
///     2. Check if CPUID.07H.00H:EDX[bit 15] sets. This bit means the processor is identified as a
///        hybrid part.
///     3. Check if CPUID.1AH:EAX sets. The hybrid core type is set in EAX.
///
/// # Arguments
///
/// * - `cpuid` the wrapped cpuid functions used to get CPUID info.
pub fn check_host_hybrid_support(cpuid: &CpuIdCall) -> std::result::Result<(), HybridSupportError> {
    // CPUID.0H.EAX returns maximum input value for basic CPUID information.
    //
    // SAFETY:
    // Safe because we pass 0 for this call and the host supports the
    // `cpuid` instruction.
    let mut cpuid_entry = unsafe { (cpuid.cpuid)(0x0) };
    if cpuid_entry.eax < 0x1A {
        return Err(HybridSupportError::UnsupportedHostCpu);
    }
    // SAFETY:
    // Safe because we pass 0x7 and 0 for this call and the host supports the
    // `cpuid` instruction.
    cpuid_entry = unsafe { (cpuid.cpuid_count)(0x7, 0) };
    if cpuid_entry.edx & 1 << EDX_HYBRID_CPU_SHIFT == 0 {
        return Err(HybridSupportError::UnsupportedHostCpu);
    }
    // From SDM, if a value entered for CPUID.EAX is less than or equal to the
    // maximum input value and the leaf is not supported on that processor then
    // 0 is returned in all the registers.
    // For the CPU with hybrid support, its CPUID.1AH.EAX shouldn't be zero.
    //
    // SAFETY:
    // Safe because we pass 0 for this call and the host supports the
    // `cpuid` instruction.
    cpuid_entry = unsafe { (cpuid.cpuid)(0x1A) };
    if cpuid_entry.eax == 0 {
        return Err(HybridSupportError::UnsupportedHostCpu);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    fn setup() -> ArchMemoryLayout {
        let pci_config = PciConfig {
            ecam: Some(MemoryRegionConfig {
                start: 3 * GB,
                size: Some(256 * MB),
            }),
            mem: Some(MemoryRegionConfig {
                start: 2 * GB,
                size: None,
            }),
        };
        create_arch_memory_layout(&pci_config, false).unwrap()
    }

    #[test]
    fn regions_lt_4gb_nobios() {
        let arch_memory_layout = setup();
        let regions = arch_memory_regions(&arch_memory_layout, 512 * MB, /* bios_size */ None);
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    512 * MB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                )
            ]
        );
    }

    #[test]
    fn regions_gt_4gb_nobios() {
        let arch_memory_layout = setup();
        let size = 4 * GB + 0x8000;
        let regions = arch_memory_regions(&arch_memory_layout, size, /* bios_size */ None);
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    2 * GB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(4 * GB),
                    2 * GB + 0x8000,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
            ]
        );
    }

    #[test]
    fn regions_lt_4gb_bios() {
        let arch_memory_layout = setup();
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(&arch_memory_layout, 512 * MB, Some(bios_len));
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    512 * MB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(4 * GB - bios_len),
                    bios_len,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::Bios,
                        file_backed: None,
                    },
                ),
            ]
        );
    }

    #[test]
    fn regions_gt_4gb_bios() {
        let arch_memory_layout = setup();
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(&arch_memory_layout, 4 * GB + 0x8000, Some(bios_len));
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    2 * GB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(4 * GB - bios_len),
                    bios_len,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::Bios,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(4 * GB),
                    2 * GB + 0x8000,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
            ]
        );
    }

    #[test]
    fn regions_eq_4gb_nobios() {
        let arch_memory_layout = setup();
        // Test with exact size of 4GB - the overhead.
        let regions = arch_memory_regions(&arch_memory_layout, 2 * GB, /* bios_size */ None);
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    2 * GB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                )
            ]
        );
    }

    #[test]
    fn regions_eq_4gb_bios() {
        let arch_memory_layout = setup();
        // Test with exact size of 4GB - the overhead.
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(&arch_memory_layout, 2 * GB, Some(bios_len));
        assert_eq!(
            regions,
            [
                (
                    GuestAddress(0),
                    640 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(640 * KB),
                    384 * KB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::ReservedMemory,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(1 * MB),
                    2 * GB - 1 * MB,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::GuestMemoryRegion,
                        file_backed: None,
                    },
                ),
                (
                    GuestAddress(4 * GB - bios_len),
                    bios_len,
                    MemoryRegionOptions {
                        align: 0,
                        purpose: MemoryRegionPurpose::Bios,
                        file_backed: None,
                    },
                ),
            ]
        );
    }

    #[test]
    fn check_pci_mmio_layout() {
        let arch_memory_layout = setup();

        assert_eq!(arch_memory_layout.pci_mmio_before_32bit.start, 2 * GB);
        assert_eq!(arch_memory_layout.pcie_cfg_mmio.start, 3 * GB);
        assert_eq!(arch_memory_layout.pcie_cfg_mmio.len().unwrap(), 256 * MB);
    }

    #[test]
    fn check_32bit_gap_size_alignment() {
        let arch_memory_layout = setup();
        // pci_mmio_before_32bit is 256 MB aligned to be friendly for MTRR mappings.
        assert_eq!(
            arch_memory_layout.pci_mmio_before_32bit.start % (256 * MB),
            0
        );
    }

    #[test]
    fn write_setup_data_empty() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x2_0000)]).unwrap();
        let setup_data = [];
        let setup_data_addr = write_setup_data(
            &mem,
            GuestAddress(0x1000),
            GuestAddress(0x2000),
            &setup_data,
        )
        .expect("write_setup_data");
        assert_eq!(setup_data_addr, None);
    }

    #[test]
    fn write_setup_data_two_of_them() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x2_0000)]).unwrap();

        let entry1_addr = GuestAddress(0x1000);
        let entry1_next_addr = entry1_addr;
        let entry1_len_addr = entry1_addr.checked_add(12).unwrap();
        let entry1_data_addr = entry1_addr.checked_add(16).unwrap();
        let entry1_data = [0x55u8; 13];
        let entry1_size = (size_of::<setup_data_hdr>() + entry1_data.len()) as u64;
        let entry1_align = 3;

        let entry2_addr = GuestAddress(entry1_addr.offset() + entry1_size + entry1_align);
        let entry2_next_addr = entry2_addr;
        let entry2_len_addr = entry2_addr.checked_add(12).unwrap();
        let entry2_data_addr = entry2_addr.checked_add(16).unwrap();
        let entry2_data = [0xAAu8; 9];

        let setup_data = [
            SetupData {
                data: entry1_data.to_vec(),
                type_: SetupDataType::Dtb,
            },
            SetupData {
                data: entry2_data.to_vec(),
                type_: SetupDataType::Dtb,
            },
        ];

        let setup_data_head_addr = write_setup_data(
            &mem,
            GuestAddress(0x1000),
            GuestAddress(0x2000),
            &setup_data,
        )
        .expect("write_setup_data");
        assert_eq!(setup_data_head_addr, Some(entry1_addr));

        assert_eq!(
            mem.read_obj_from_addr::<u64>(entry1_next_addr).unwrap(),
            entry2_addr.offset()
        );
        assert_eq!(
            mem.read_obj_from_addr::<u32>(entry1_len_addr).unwrap(),
            entry1_data.len() as u32
        );
        assert_eq!(
            mem.read_obj_from_addr::<[u8; 13]>(entry1_data_addr)
                .unwrap(),
            entry1_data
        );

        assert_eq!(mem.read_obj_from_addr::<u64>(entry2_next_addr).unwrap(), 0);
        assert_eq!(
            mem.read_obj_from_addr::<u32>(entry2_len_addr).unwrap(),
            entry2_data.len() as u32
        );
        assert_eq!(
            mem.read_obj_from_addr::<[u8; 9]>(entry2_data_addr).unwrap(),
            entry2_data
        );
    }

    #[test]
    fn cmdline_overflow() {
        const MEM_SIZE: u64 = 0x1000;
        let gm = GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap();
        let mut cmdline = kernel_cmdline::Cmdline::new();
        cmdline.insert_str("12345").unwrap();
        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        let err =
            X8664arch::load_cmdline(&gm, cmdline_address, cmdline, CMDLINE_MAX_SIZE as usize - 1)
                .unwrap_err();
        assert!(matches!(err, Error::CommandLineOverflow));
    }

    #[test]
    fn cmdline_write_end() {
        const MEM_SIZE: u64 = 0x1000;
        let gm = GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap();
        let mut cmdline = kernel_cmdline::Cmdline::new();
        cmdline.insert_str("1234").unwrap();
        let mut cmdline_address = GuestAddress(45);
        X8664arch::load_cmdline(&gm, cmdline_address, cmdline, CMDLINE_MAX_SIZE as usize - 1)
            .unwrap();
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }
}
