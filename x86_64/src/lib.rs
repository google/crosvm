// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! x86 architecture support.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

mod fdt;

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

#[cfg(unix)]
pub mod msr;

pub mod acpi;
mod bzimage;
pub mod cpuid;
mod gdt;
pub mod interrupts;
pub mod mptable;
pub mod regs;
pub mod smbios;

use std::arch::x86_64::CpuidResult;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Seek;
use std::mem;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use acpi_tables::sdt::SDT;
use anyhow::Context;
use arch::get_serial_cmdline;
use arch::GetSerialCmdlineError;
use arch::MsrAction;
use arch::MsrConfig;
use arch::MsrFilter;
use arch::MsrRWType;
use arch::MsrValueFrom;
use arch::RunnableLinuxVm;
use arch::VmComponents;
use arch::VmImage;
#[cfg(feature = "seccomp_trace")]
use base::debug;
use base::warn;
#[cfg(unix)]
use base::AsRawDescriptors;
use base::Event;
use base::SendTube;
use base::Tube;
use base::TubeError;
use chrono::Utc;
pub use cpuid::adjust_cpuid;
pub use cpuid::CpuIdContext;
use devices::BusDevice;
use devices::BusDeviceObj;
use devices::BusResumeDevice;
use devices::Debugcon;
use devices::FwCfgParameters;
use devices::IrqChip;
use devices::IrqChipX86_64;
use devices::IrqEventSource;
use devices::PciAddress;
use devices::PciConfigIo;
use devices::PciConfigMmio;
use devices::PciDevice;
use devices::PciRoot;
use devices::PciRootCommand;
use devices::PciVirtualConfigMmio;
use devices::Pflash;
#[cfg(unix)]
use devices::ProxyDevice;
use devices::Serial;
use devices::SerialHardware;
use devices::SerialParameters;
#[cfg(unix)]
use devices::VirtualPmc;
#[cfg(feature = "gdb")]
use gdbstub_arch::x86::reg::id::X86_64CoreRegId;
#[cfg(feature = "gdb")]
use gdbstub_arch::x86::reg::X86SegmentRegs;
#[cfg(feature = "gdb")]
use gdbstub_arch::x86::reg::X86_64CoreRegs;
#[cfg(feature = "gdb")]
use gdbstub_arch::x86::reg::X87FpuInternalRegs;
#[cfg(feature = "gdb")]
use hypervisor::x86_64::Regs;
#[cfg(feature = "gdb")]
use hypervisor::x86_64::Sregs;
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
#[cfg(unix)]
use minijail::Minijail;
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use rand::RngCore;
use remain::sorted;
use resources::AddressRange;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
#[cfg(unix)]
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_control::BatControl;
use vm_control::BatteryType;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use vm_memory::MemoryRegionOptions;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::bootparam::boot_params;
use crate::cpuid::EDX_HYBRID_CPU_SHIFT;
use crate::msr_index::*;

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
    #[cfg(unix)]
    #[error("failed to clone jail: {0}")]
    CloneJail(minijail::Error),
    #[error("unable to clone a Tube: {0}")]
    CloneTube(TubeError),
    #[error("the given kernel command line was invalid: {0}")]
    Cmdline(kernel_cmdline::Error),
    #[error("failed to configure hotplugged pci device: {0}")]
    ConfigurePciDevice(arch::DeviceRegistrationError),
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
    #[error("failed to create IOAPIC device: {0}")]
    CreateIoapicDevice(base::Error),
    #[error("failed to create a PCI root hub: {0}")]
    CreatePciRoot(arch::DeviceRegistrationError),
    #[error("unable to create PIT: {0}")]
    CreatePit(base::Error),
    #[error("unable to make PIT device: {0}")]
    CreatePitDevice(devices::PitError),
    #[cfg(unix)]
    #[error("unable to create proxy device: {0}")]
    CreateProxyDevice(devices::ProxyError),
    #[error("unable to create serial devices: {0}")]
    CreateSerialDevices(arch::DeviceRegistrationError),
    #[error("failed to create socket: {0}")]
    CreateSocket(io::Error),
    #[error("failed to create VCPU: {0}")]
    CreateVcpu(base::Error),
    #[error("failed to create Virtio MMIO bus: {0}")]
    CreateVirtioMmioBus(arch::DeviceRegistrationError),
    #[error("invalid e820 setup params")]
    E820Configuration,
    #[cfg(feature = "direct")]
    #[error("failed to enable ACPI event forwarding: {0}")]
    EnableAcpiEvent(devices::DirectIrqError),
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
    #[error("error loading command line: {0}")]
    LoadCmdline(kernel_loader::Error),
    #[error("error loading initrd: {0}")]
    LoadInitrd(arch::LoadImageError),
    #[error("error loading Kernel: {0}")]
    LoadKernel(kernel_loader::Error),
    #[error("error loading pflash: {0}")]
    LoadPflash(io::Error),
    #[error("error translating address: Page not present")]
    PageNotPresent,
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
#[derive(Copy, Clone, Default, FromBytes, AsBytes)]
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

enum E820Type {
    Ram = 0x01,
    Reserved = 0x2,
}

const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;

pub const BOOT_STACK_POINTER: u64 = 0x8000;
const START_OF_RAM_32BITS: u64 = 0;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
// Linux (with 4-level paging) has a physical memory limit of 46 bits (64 TiB).
const HIGH_MMIO_MAX_END: u64 = (1u64 << 46) - 1;
pub const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;
pub const ZERO_PAGE_OFFSET: u64 = 0x7000;
const TSS_ADDR: u64 = 0xfffb_d000;

pub const KERNEL_START_OFFSET: u64 = 0x20_0000;
const CMDLINE_OFFSET: u64 = 0x2_0000;
const CMDLINE_MAX_SIZE: u64 = 0x800; // including terminating zero
const SETUP_DATA_START: u64 = CMDLINE_OFFSET + CMDLINE_MAX_SIZE;
const SETUP_DATA_END: u64 = ACPI_HI_RSDP_WINDOW_BASE;
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

#[derive(Debug, PartialEq, Eq)]
pub enum CpuManufacturer {
    Intel,
    Amd,
    Unknown,
}

pub fn get_cpu_manufacturer() -> CpuManufacturer {
    cpuid::cpu_manufacturer()
}

// Memory layout below 4G
struct LowMemoryLayout {
    // the pci mmio range below 4G
    pci_mmio: AddressRange,
    // the pcie cfg mmio range
    pcie_cfg_mmio: AddressRange,
}

static LOW_MEMORY_LAYOUT: OnceCell<LowMemoryLayout> = OnceCell::new();

pub fn init_low_memory_layout(pcie_ecam: Option<AddressRange>, pci_low_start: Option<u64>) {
    LOW_MEMORY_LAYOUT.get_or_init(|| {
        // Make sure it align to 256MB for MTRR convenient
        const MEM_32BIT_GAP_SIZE: u64 = 768 * MB;
        // Reserved memory for nand_bios/LAPIC/IOAPIC/HPET/.....
        const RESERVED_MEM_SIZE: u64 = 0x800_0000;
        const PCI_MMIO_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
        // Reserve 64MB for pcie enhanced configuration
        const DEFAULT_PCIE_CFG_MMIO_SIZE: u64 = 0x400_0000;
        const DEFAULT_PCIE_CFG_MMIO_END: u64 = FIRST_ADDR_PAST_32BITS - RESERVED_MEM_SIZE - 1;
        const DEFAULT_PCIE_CFG_MMIO_START: u64 =
            DEFAULT_PCIE_CFG_MMIO_END - DEFAULT_PCIE_CFG_MMIO_SIZE + 1;
        const DEFAULT_PCIE_CFG_MMIO: AddressRange = AddressRange {
            start: DEFAULT_PCIE_CFG_MMIO_START,
            end: DEFAULT_PCIE_CFG_MMIO_END,
        };

        let pcie_cfg_mmio = pcie_ecam.unwrap_or(DEFAULT_PCIE_CFG_MMIO);

        let pci_mmio = if let Some(pci_low) = pci_low_start {
            AddressRange {
                start: pci_low,
                end: PCI_MMIO_END,
            }
        } else {
            AddressRange {
                start: pcie_cfg_mmio
                    .start
                    .min(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE),
                end: PCI_MMIO_END,
            }
        };

        LowMemoryLayout {
            pci_mmio,
            pcie_cfg_mmio,
        }
    });
}

pub fn read_pci_mmio_before_32bit() -> AddressRange {
    LOW_MEMORY_LAYOUT.get().unwrap().pci_mmio
}
pub fn read_pcie_cfg_mmio() -> AddressRange {
    LOW_MEMORY_LAYOUT.get().unwrap().pcie_cfg_mmio
}

/// The x86 reset vector for i386+ and x86_64 puts the processor into an "unreal mode" where it
/// can access the last 1 MB of the 32-bit address space in 16-bit mode, and starts the instruction
/// pointer at the effective physical address 0xFFFF_FFF0.
fn bios_start(bios_size: u64) -> GuestAddress {
    GuestAddress(FIRST_ADDR_PAST_32BITS - bios_size)
}

fn configure_system(
    guest_mem: &GuestMemory,
    kernel_addr: GuestAddress,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    setup_data: Option<GuestAddress>,
    initrd: Option<(GuestAddress, usize)>,
    mut params: boot_params,
) -> Result<()> {
    const EBDA_START: u64 = 0x0009_fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x100_0000; // Must be non-zero.

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.ext_cmd_line_ptr = (cmdline_addr.offset() >> 32) as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(setup_data) = setup_data {
        params.hdr.setup_data = setup_data.offset();
    }
    if let Some((initrd_addr, initrd_size)) = initrd {
        params.hdr.ramdisk_image = initrd_addr.offset() as u32;
        params.hdr.ramdisk_size = initrd_size as u32;
    }

    add_e820_entry(
        &mut params,
        AddressRange {
            start: START_OF_RAM_32BITS,
            end: EBDA_START - 1,
        },
        E820Type::Ram,
    )?;

    // GuestMemory::end_addr() returns the first address past the end, so subtract 1 to get the
    // inclusive end.
    let guest_mem_end = guest_mem.end_addr().offset() - 1;
    let ram_below_4g = AddressRange {
        start: kernel_addr.offset(),
        end: guest_mem_end.min(read_pci_mmio_before_32bit().start - 1),
    };
    let ram_above_4g = AddressRange {
        start: FIRST_ADDR_PAST_32BITS,
        end: guest_mem_end,
    };
    add_e820_entry(&mut params, ram_below_4g, E820Type::Ram)?;
    if !ram_above_4g.is_empty() {
        add_e820_entry(&mut params, ram_above_4g, E820Type::Ram)?
    }

    let pcie_cfg_mmio_range = read_pcie_cfg_mmio();
    add_e820_entry(&mut params, pcie_cfg_mmio_range, E820Type::Reserved)?;

    add_e820_entry(
        &mut params,
        X8664arch::get_pcie_vcfg_mmio_range(guest_mem, &pcie_cfg_mmio_range),
        E820Type::Reserved,
    )?;

    let zero_page_addr = GuestAddress(ZERO_PAGE_OFFSET);
    if !guest_mem.is_valid_range(zero_page_addr, mem::size_of::<boot_params>() as u64) {
        return Err(Error::ZeroPagePastRamEnd);
    }

    guest_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
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
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, range: AddressRange, mem_type: E820Type) -> Result<()> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::E820Configuration);
    }

    let size = range.len().ok_or(Error::E820Configuration)?;

    params.e820_table[params.e820_entries as usize].addr = range.start;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type as u32;
    params.e820_entries += 1;

    Ok(())
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(
    size: u64,
    bios_size: Option<u64>,
) -> Vec<(GuestAddress, u64, MemoryRegionOptions)> {
    let mem_start = START_OF_RAM_32BITS;
    let mem_end = GuestAddress(size + mem_start);

    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(read_pci_mmio_before_32bit().start);

    let mut regions = Vec::new();
    if mem_end <= end_32bit_gap_start {
        regions.push((GuestAddress(mem_start), size, Default::default()));
        if let Some(bios_size) = bios_size {
            regions.push((bios_start(bios_size), bios_size, Default::default()));
        }
    } else {
        regions.push((
            GuestAddress(mem_start),
            end_32bit_gap_start.offset() - mem_start,
            Default::default(),
        ));
        if let Some(bios_size) = bios_size {
            regions.push((bios_start(bios_size), bios_size, Default::default()));
        }
        regions.push((
            first_addr_past_32bits,
            mem_end.offset_from(end_32bit_gap_start),
            Default::default(),
        ));
    }

    regions
}

impl arch::LinuxArch for X8664arch {
    type Error = Error;

    fn guest_memory_layout(
        components: &VmComponents,
        _hypervisor: &impl Hypervisor,
    ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
        init_low_memory_layout(components.pcie_ecam, components.pci_low_start);

        let bios_size = match &components.vm_image {
            VmImage::Bios(bios_file) => Some(bios_file.metadata().map_err(Error::LoadBios)?.len()),
            VmImage::Kernel(_) => None,
        };

        Ok(arch_memory_regions(components.memory_size, bios_size))
    }

    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xffff,
            }),
            low_mmio: read_pci_mmio_before_32bit(),
            high_mmio: Self::get_high_mmio_range(vm),
            platform_mmio: None,
            first_irq: X86_64_IRQ_BASE,
        }
    }

    fn build_vm<V, Vcpu>(
        mut components: VmComponents,
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
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        #[cfg(unix)] guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmX86_64,
        Vcpu: VcpuX86_64,
    {
        if components.hv_cfg.protection_type != ProtectionType::Unprotected {
            return Err(Error::UnsupportedProtectionType);
        }

        let mem = vm.get_memory().clone();

        let vcpu_count = components.vcpu_count;

        let tss_addr = GuestAddress(TSS_ADDR);
        vm.set_tss_addr(tss_addr).map_err(Error::SetTssAddr)?;

        // Use IRQ info in ACPI if provided by the user.
        let mut noirq = true;
        let mut mptable = true;
        let mut sci_irq = X86_64_SCI_IRQ;

        // punch pcie config mmio from pci low mmio, so that it couldn't be
        // allocated to any device.
        let pcie_cfg_mmio_range = read_pcie_cfg_mmio();
        system_allocator
            .reserve_mmio(pcie_cfg_mmio_range)
            .map_err(Error::ReservePcieCfgMmio)?;

        for sdt in components.acpi_sdts.iter() {
            if sdt.is_signature(b"DSDT") || sdt.is_signature(b"APIC") {
                noirq = false;
            } else if sdt.is_signature(b"FACP") {
                mptable = false;
                let sci_irq_fadt: u16 = sdt.read(acpi::FADT_FIELD_SCI_INTERRUPT);
                sci_irq = sci_irq_fadt.into();
                if !system_allocator.reserve_irq(sci_irq) {
                    warn!("sci irq {} already reserved.", sci_irq);
                }
            }
        }

        let pcie_vcfg_range = Self::get_pcie_vcfg_mmio_range(&mem, &pcie_cfg_mmio_range);
        let mmio_bus = Arc::new(devices::Bus::new());
        let io_bus = Arc::new(devices::Bus::new());

        let (pci_devices, devs): (Vec<_>, Vec<_>) = devs
            .into_iter()
            .partition(|(dev, _)| dev.as_pci_device().is_some());

        let pci_devices = pci_devices
            .into_iter()
            .map(|(dev, jail_orig)| (dev.into_pci_device().unwrap(), jail_orig))
            .collect();

        let (pci, pci_irqs, mut pid_debug_label_map, amls) = arch::generate_pci_root(
            pci_devices,
            irq_chip.as_irq_chip_mut(),
            mmio_bus.clone(),
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

        let (virtio_mmio_devices, _others): (Vec<_>, Vec<_>) = devs
            .into_iter()
            .partition(|(dev, _)| dev.as_virtio_mmio_device().is_some());

        let virtio_mmio_devices = virtio_mmio_devices
            .into_iter()
            .map(|(dev, jail_orig)| (*(dev.into_virtio_mmio_device().unwrap()), jail_orig))
            .collect();
        let (mut virtio_mmio_pid, sdts) = arch::generate_virtio_mmio_bus(
            virtio_mmio_devices,
            irq_chip.as_irq_chip_mut(),
            &mmio_bus,
            system_allocator,
            &mut vm,
            components.acpi_sdts,
            #[cfg(feature = "swap")]
            swap_controller,
        )
        .map_err(Error::CreateVirtioMmioBus)?;
        components.acpi_sdts = sdts;
        pid_debug_label_map.append(&mut virtio_mmio_pid);

        // Event used to notify crosvm that guest OS is trying to suspend.
        let suspend_evt = Event::new().map_err(Error::CreateEvent)?;

        if !components.fw_cfg_parameters.is_empty() {
            Self::setup_fw_cfg_device(&io_bus, components.fw_cfg_parameters.clone())?;
        }

        if !components.no_i8042 {
            Self::setup_legacy_i8042_device(
                &io_bus,
                irq_chip.pit_uses_speaker_port(),
                vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
            )?;
        }
        let vm_request_tube = if !components.no_rtc {
            let (host_tube, device_tube) = Tube::pair()
                .context("create tube")
                .map_err(Error::SetupCmos)?;
            Self::setup_legacy_cmos_device(&io_bus, irq_chip, device_tube, components.memory_size)
                .map_err(Error::SetupCmos)?;
            Some(host_tube)
        } else {
            None
        };
        Self::setup_serial_devices(
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
            pci.clone(),
            &mem,
            &io_bus,
            system_allocator,
            suspend_evt.try_clone().map_err(Error::CloneEvent)?,
            vm_evt_wrtube.try_clone().map_err(Error::CloneTube)?,
            components.acpi_sdts,
            #[cfg(feature = "direct")]
            &components.direct_gpe,
            #[cfg(feature = "direct")]
            &components.direct_fixed_evts,
            irq_chip.as_irq_chip_mut(),
            sci_irq,
            battery,
            &mmio_bus,
            max_bus,
            &mut resume_notify_devices,
            #[cfg(feature = "swap")]
            swap_controller,
            #[cfg(unix)]
            components.ac_adapter,
            #[cfg(unix)]
            guest_suspended_cvar,
        )?;

        // Create customized SSDT table
        let sdt = acpi::create_customize_ssdt(pci.clone(), amls);
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

        if mptable {
            // Note that this puts the mptable at 0x9FC00 in guest physical memory.
            mptable::setup_mptable(&mem, vcpu_count as u8, &pci_irqs)
                .map_err(Error::SetupMptable)?;
        }
        smbios::setup_smbios(&mem, &components.oem_strings).map_err(Error::SetupSmbios)?;

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

        if noirq {
            cmdline.insert_str("acpi=noirq").unwrap();
        }

        get_serial_cmdline(&mut cmdline, serial_parameters, "io")
            .map_err(Error::GetSerialCmdline)?;

        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        if let Some(ramoops_region) = ramoops_region {
            arch::pstore::add_ramoops_kernel_cmdline(&mut cmdline, &ramoops_region)
                .map_err(Error::Cmdline)?;
        }

        let pci_start = read_pci_mmio_before_32bit().start;

        let mut vcpu_init = vec![VcpuInitX86_64::default(); vcpu_count];

        let mut msrs;
        match components.vm_image {
            VmImage::Bios(ref mut bios) => {
                // Allow a bios to hardcode CMDLINE_OFFSET and read the kernel command line from it.
                kernel_loader::load_cmdline(
                    &mem,
                    GuestAddress(CMDLINE_OFFSET),
                    &CString::new(cmdline).unwrap(),
                )
                .map_err(Error::LoadCmdline)?;
                Self::load_bios(&mem, bios)?;
                msrs = regs::default_msrs();
                // The default values for `Regs` and `Sregs` already set up the reset vector.
            }
            VmImage::Kernel(ref mut kernel_image) => {
                let (params, kernel_end, kernel_entry) = Self::load_kernel(&mem, kernel_image)?;

                Self::setup_system_memory(
                    &mem,
                    &CString::new(cmdline).unwrap(),
                    components.initrd_image,
                    components.android_fstab,
                    kernel_end,
                    params,
                    dump_device_tree_blob,
                )?;

                // Configure the bootstrap VCPU for the Linux/x86 64-bit boot protocol.
                // <https://www.kernel.org/doc/html/latest/x86/boot.html>
                vcpu_init[0].regs.rip = kernel_entry.offset();
                vcpu_init[0].regs.rsp = BOOT_STACK_POINTER;
                vcpu_init[0].regs.rsi = ZERO_PAGE_OFFSET;

                msrs = regs::long_mode_msrs();
                msrs.append(&mut regs::mtrr_msrs(&vm, pci_start));

                // Set up long mode and enable paging.
                regs::configure_segments_and_sregs(&mem, &mut vcpu_init[0].sregs)
                    .map_err(Error::ConfigureSegments)?;
                regs::setup_page_tables(&mem, &mut vcpu_init[0].sregs)
                    .map_err(Error::SetupPageTables)?;
            }
        }

        // Initialize MSRs for all VCPUs.
        for vcpu in vcpu_init.iter_mut() {
            vcpu.msrs = msrs.clone();
        }

        Ok(RunnableLinuxVm {
            vm,
            vcpu_count,
            vcpus: None,
            vcpu_affinity: components.vcpu_affinity,
            vcpu_init,
            no_smt: components.no_smt,
            irq_chip: irq_chip.try_box_clone().map_err(Error::CloneIrqChip)?,
            has_bios: matches!(components.vm_image, VmImage::Bios(_)),
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            suspend_evt,
            resume_notify_devices,
            rt_cpus: components.rt_cpus,
            delay_rt: components.delay_rt,
            bat_control,
            #[cfg(feature = "gdb")]
            gdb: components.gdb,
            pm: Some(acpi_dev_resource.pm),
            root_config: pci,
            #[cfg(unix)]
            platform_devices: Vec::new(),
            hotplug_bus: BTreeMap::new(),
            devices_thread: None,
            vm_request_tube,
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
        _has_bios: bool,
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
        let msrs = if num_var_mtrrs > vcpu_supported_var_mtrrs {
            warn!(
                "Too many variable MTRR entries ({} required, {} supported),
                please check pci_start addr, guest with pass through device may be very slow",
                num_var_mtrrs, vcpu_supported_var_mtrrs,
            );
            // Filter out the MTRR entries from the MSR list.
            vcpu_init
                .msrs
                .into_iter()
                .filter(|&msr| !regs::is_mtrr_msr(msr.id))
                .collect()
        } else {
            vcpu_init.msrs
        };

        vcpu.set_msrs(&msrs).map_err(Error::SetupMsrs)?;

        interrupts::set_lint(vcpu_id, irq_chip).map_err(Error::SetLint)?;

        Ok(())
    }

    fn register_pci_device<V: VmX86_64, Vcpu: VcpuX86_64>(
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        device: Box<dyn PciDevice>,
        #[cfg(unix)] minijail: Option<Minijail>,
        resources: &mut SystemAllocator,
        hp_control_tube: &mpsc::Sender<PciRootCommand>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<PciAddress> {
        arch::configure_pci_device(
            linux,
            device,
            #[cfg(unix)]
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
}

#[cfg(feature = "gdb")]
impl<T: VcpuX86_64> arch::GdbOps<T> for X8664arch {
    type Error = Error;

    fn read_registers(vcpu: &T) -> Result<X86_64CoreRegs> {
        // General registers: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
        let gregs = vcpu.get_regs().map_err(Error::ReadRegs)?;
        let regs = [
            gregs.rax, gregs.rbx, gregs.rcx, gregs.rdx, gregs.rsi, gregs.rdi, gregs.rbp, gregs.rsp,
            gregs.r8, gregs.r9, gregs.r10, gregs.r11, gregs.r12, gregs.r13, gregs.r14, gregs.r15,
        ];

        // GDB exposes 32-bit eflags instead of 64-bit rflags.
        // https://github.com/bminor/binutils-gdb/blob/master/gdb/features/i386/64bit-core.xml
        let eflags = gregs.rflags as u32;
        let rip = gregs.rip;

        // Segment registers: CS, SS, DS, ES, FS, GS
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let segments = X86SegmentRegs {
            cs: sregs.cs.selector as u32,
            ss: sregs.ss.selector as u32,
            ds: sregs.ds.selector as u32,
            es: sregs.es.selector as u32,
            fs: sregs.fs.selector as u32,
            gs: sregs.gs.selector as u32,
        };

        // x87 FPU internal state
        // TODO(dverkamp): floating point tag word, instruction pointer, and data pointer
        let fpu = vcpu.get_fpu().map_err(Error::ReadRegs)?;
        let fpu_internal = X87FpuInternalRegs {
            fctrl: u32::from(fpu.fcw),
            fstat: u32::from(fpu.fsw),
            fop: u32::from(fpu.last_opcode),
            ..Default::default()
        };

        let mut regs = X86_64CoreRegs {
            regs,
            eflags,
            rip,
            segments,
            st: Default::default(),
            fpu: fpu_internal,
            xmm: Default::default(),
            mxcsr: fpu.mxcsr,
        };

        // x87 FPU registers: ST0-ST7
        for (dst, src) in regs.st.iter_mut().zip(fpu.fpr.iter()) {
            // `fpr` contains the x87 floating point registers in FXSAVE format.
            // Each element contains an 80-bit floating point value in the low 10 bytes.
            // The upper 6 bytes are reserved and can be ignored.
            dst.copy_from_slice(&src[0..10])
        }

        // SSE registers: XMM0-XMM15
        for (dst, src) in regs.xmm.iter_mut().zip(fpu.xmm.iter()) {
            *dst = u128::from_le_bytes(*src);
        }

        Ok(regs)
    }

    fn write_registers(vcpu: &T, regs: &X86_64CoreRegs) -> Result<()> {
        // General purpose registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15) + RIP + rflags
        let orig_gregs = vcpu.get_regs().map_err(Error::ReadRegs)?;
        let gregs = Regs {
            rax: regs.regs[0],
            rbx: regs.regs[1],
            rcx: regs.regs[2],
            rdx: regs.regs[3],
            rsi: regs.regs[4],
            rdi: regs.regs[5],
            rbp: regs.regs[6],
            rsp: regs.regs[7],
            r8: regs.regs[8],
            r9: regs.regs[9],
            r10: regs.regs[10],
            r11: regs.regs[11],
            r12: regs.regs[12],
            r13: regs.regs[13],
            r14: regs.regs[14],
            r15: regs.regs[15],
            rip: regs.rip,
            // Update the lower 32 bits of rflags.
            rflags: (orig_gregs.rflags & !(u32::MAX as u64)) | (regs.eflags as u64),
        };
        vcpu.set_regs(&gregs).map_err(Error::WriteRegs)?;

        // Segment registers: CS, SS, DS, ES, FS, GS
        // Since GDB care only selectors, we call get_sregs() first.
        let mut sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        sregs.cs.selector = regs.segments.cs as u16;
        sregs.ss.selector = regs.segments.ss as u16;
        sregs.ds.selector = regs.segments.ds as u16;
        sregs.es.selector = regs.segments.es as u16;
        sregs.fs.selector = regs.segments.fs as u16;
        sregs.gs.selector = regs.segments.gs as u16;

        vcpu.set_sregs(&sregs).map_err(Error::WriteRegs)?;

        // FPU and SSE registers
        let mut fpu = vcpu.get_fpu().map_err(Error::ReadRegs)?;
        fpu.fcw = regs.fpu.fctrl as u16;
        fpu.fsw = regs.fpu.fstat as u16;
        fpu.last_opcode = regs.fpu.fop as u16;
        // TODO(dverkamp): floating point tag word, instruction pointer, and data pointer

        // x87 FPU registers: ST0-ST7
        for (dst, src) in fpu.fpr.iter_mut().zip(regs.st.iter()) {
            dst[0..10].copy_from_slice(src);
        }

        // SSE registers: XMM0-XMM15
        for (dst, src) in fpu.xmm.iter_mut().zip(regs.xmm.iter()) {
            dst.copy_from_slice(&src.to_le_bytes());
        }

        vcpu.set_fpu(&fpu).map_err(Error::WriteRegs)?;

        Ok(())
    }

    #[inline]
    fn read_register(_vcpu: &T, _reg: X86_64CoreRegId) -> Result<Vec<u8>> {
        Err(Error::ReadRegIsUnsupported)
    }

    #[inline]
    fn write_register(_vcpu: &T, _reg: X86_64CoreRegId, _buf: &[u8]) -> Result<()> {
        Err(Error::WriteRegIsUnsupported)
    }

    fn read_memory(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        len: usize,
    ) -> Result<Vec<u8>> {
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let mut buf = vec![0; len];
        let mut total_read = 0u64;
        // Handle reads across page boundaries.

        while total_read < len as u64 {
            let (paddr, psize) = phys_addr(guest_mem, vaddr.0 + total_read, &sregs)?;
            let read_len = std::cmp::min(len as u64 - total_read, psize - (paddr & (psize - 1)));
            guest_mem
                .get_slice_at_addr(GuestAddress(paddr), read_len as usize)
                .map_err(Error::ReadingGuestMemory)?
                .copy_to(&mut buf[total_read as usize..]);
            total_read += read_len;
        }
        Ok(buf)
    }

    fn write_memory(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        buf: &[u8],
    ) -> Result<()> {
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let mut total_written = 0u64;
        // Handle writes across page boundaries.
        while total_written < buf.len() as u64 {
            let (paddr, psize) = phys_addr(guest_mem, vaddr.0 + total_written, &sregs)?;
            let write_len = std::cmp::min(
                buf.len() as u64 - total_written,
                psize - (paddr & (psize - 1)),
            );

            guest_mem
                .write_all_at_addr(
                    &buf[total_written as usize..(total_written as usize + write_len as usize)],
                    GuestAddress(paddr),
                )
                .map_err(Error::WritingGuestMemory)?;
            total_written += write_len;
        }
        Ok(())
    }

    fn enable_singlestep(vcpu: &T) -> Result<()> {
        vcpu.set_guest_debug(&[], true /* enable_singlestep */)
            .map_err(Error::EnableSinglestep)
    }

    fn get_max_hw_breakpoints(_vcpu: &T) -> Result<usize> {
        Ok(4usize)
    }

    fn set_hw_breakpoints(vcpu: &T, breakpoints: &[GuestAddress]) -> Result<()> {
        vcpu.set_guest_debug(breakpoints, false /* enable_singlestep */)
            .map_err(Error::SetHwBreakpoint)
    }
}

#[cfg(feature = "gdb")]
// return the translated address and the size of the page it resides in.
fn phys_addr(mem: &GuestMemory, vaddr: u64, sregs: &Sregs) -> Result<(u64, u64)> {
    const CR0_PG_MASK: u64 = 1 << 31;
    const CR4_PAE_MASK: u64 = 1 << 5;
    const CR4_LA57_MASK: u64 = 1 << 12;
    const MSR_EFER_LMA: u64 = 1 << 10;
    // bits 12 through 51 are the address in a PTE.
    const PTE_ADDR_MASK: u64 = ((1 << 52) - 1) & !0x0fff;
    const PAGE_PRESENT: u64 = 0x1;
    const PAGE_PSE_MASK: u64 = 0x1 << 7;

    const PAGE_SIZE_4K: u64 = 4 * 1024;
    const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
    const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

    fn next_pte(mem: &GuestMemory, curr_table_addr: u64, vaddr: u64, level: usize) -> Result<u64> {
        let ent: u64 = mem
            .read_obj_from_addr(GuestAddress(
                (curr_table_addr & PTE_ADDR_MASK) + page_table_offset(vaddr, level),
            ))
            .map_err(|_| Error::TranslatingVirtAddr)?;
        /* TODO - convert to a trace
        println!(
            "level {} vaddr {:x} table-addr {:x} mask {:x} ent {:x} offset {:x}",
            level,
            vaddr,
            curr_table_addr,
            PTE_ADDR_MASK,
            ent,
            page_table_offset(vaddr, level)
        );
        */
        if ent & PAGE_PRESENT == 0 {
            return Err(Error::PageNotPresent);
        }
        Ok(ent)
    }

    // Get the offset in to the page of `vaddr`.
    fn page_offset(vaddr: u64, page_size: u64) -> u64 {
        vaddr & (page_size - 1)
    }

    // Get the offset in to the page table of the given `level` specified by the virtual `address`.
    // `level` is 1 through 5 in x86_64 to handle the five levels of paging.
    fn page_table_offset(addr: u64, level: usize) -> u64 {
        let offset = (level - 1) * 9 + 12;
        ((addr >> offset) & 0x1ff) << 3
    }

    if sregs.cr0 & CR0_PG_MASK == 0 {
        return Ok((vaddr, PAGE_SIZE_4K));
    }

    if sregs.cr4 & CR4_PAE_MASK == 0 {
        return Err(Error::TranslatingVirtAddr);
    }

    if sregs.efer & MSR_EFER_LMA != 0 {
        // TODO - check LA57
        if sregs.cr4 & CR4_LA57_MASK != 0 {}
        let p4_ent = next_pte(mem, sregs.cr3, vaddr, 4)?;
        let p3_ent = next_pte(mem, p4_ent, vaddr, 3)?;
        // TODO check if it's a 1G page with the PSE bit in p2_ent
        if p3_ent & PAGE_PSE_MASK != 0 {
            // It's a 1G page with the PSE bit in p3_ent
            let paddr = p3_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_1G);
            return Ok((paddr, PAGE_SIZE_1G));
        }
        let p2_ent = next_pte(mem, p3_ent, vaddr, 2)?;
        if p2_ent & PAGE_PSE_MASK != 0 {
            // It's a 2M page with the PSE bit in p2_ent
            let paddr = p2_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_2M);
            return Ok((paddr, PAGE_SIZE_2M));
        }
        let p1_ent = next_pte(mem, p2_ent, vaddr, 1)?;
        let paddr = p1_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_4K);
        return Ok((paddr, PAGE_SIZE_4K));
    }
    Err(Error::TranslatingVirtAddr)
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

impl X8664arch {
    /// Loads the bios from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `bios_image` - the File object for the specified bios
    fn load_bios(mem: &GuestMemory, bios_image: &mut File) -> Result<()> {
        let bios_image_length = bios_image
            .seek(io::SeekFrom::End(0))
            .map_err(Error::LoadBios)?;
        if bios_image_length >= FIRST_ADDR_PAST_32BITS {
            return Err(Error::LoadBios(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bios was {} bytes, expected less than {}",
                    bios_image_length, FIRST_ADDR_PAST_32BITS,
                ),
            )));
        }
        bios_image
            .seek(io::SeekFrom::Start(0))
            .map_err(Error::LoadBios)?;
        mem.read_to_memory(
            bios_start(bios_image_length),
            bios_image,
            bios_image_length as usize,
        )
        .map_err(Error::SetupGuestMemory)?;
        Ok(())
    }

    fn setup_pflash(
        pflash_image: File,
        block_size: u32,
        bios_size: u64,
        mmio_bus: &devices::Bus,
        jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<()> {
        let size = pflash_image.metadata().map_err(Error::LoadPflash)?.len();
        let start = FIRST_ADDR_PAST_32BITS - bios_size - size;
        let pflash_image = Box::new(pflash_image);

        #[cfg(unix)]
        let fds = pflash_image.as_raw_descriptors();

        let pflash = Pflash::new(pflash_image, block_size).map_err(Error::SetupPflash)?;
        let pflash: Arc<Mutex<dyn BusDevice>> = match jail {
            #[cfg(unix)]
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

    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    ///
    /// # Returns
    ///
    /// On success, returns the Linux x86_64 boot protocol parameters, the first address past the
    /// end of the kernel, and the entry point (initial `RIP` value).
    fn load_kernel(
        mem: &GuestMemory,
        kernel_image: &mut File,
    ) -> Result<(boot_params, u64, GuestAddress)> {
        let kernel_start = GuestAddress(KERNEL_START_OFFSET);
        match kernel_loader::load_elf64(mem, kernel_start, kernel_image, 0) {
            Ok(loaded_kernel) => {
                // ELF kernels don't contain a `boot_params` structure, so synthesize a default one.
                let boot_params = Default::default();
                Ok((
                    boot_params,
                    loaded_kernel.address_range.end,
                    loaded_kernel.entry,
                ))
            }
            Err(kernel_loader::Error::InvalidMagicNumber) => {
                // The image failed to parse as ELF, so try to load it as a bzImage.
                let (boot_params, bzimage_end) =
                    bzimage::load_bzimage(mem, kernel_start, kernel_image)
                        .map_err(Error::LoadBzImage)?;
                let bzimage_entry = mem
                    .checked_offset(kernel_start, KERNEL_64BIT_ENTRY_OFFSET)
                    .ok_or(Error::KernelOffsetPastEnd)?;
                Ok((boot_params, bzimage_end, bzimage_entry))
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
        mem: &GuestMemory,
        cmdline: &CStr,
        initrd_file: Option<File>,
        android_fstab: Option<File>,
        kernel_end: u64,
        params: boot_params,
        dump_device_tree_blob: Option<PathBuf>,
    ) -> Result<()> {
        kernel_loader::load_cmdline(mem, GuestAddress(CMDLINE_OFFSET), cmdline)
            .map_err(Error::LoadCmdline)?;

        let mut setup_data = Vec::<SetupData>::new();
        if let Some(android_fstab) = android_fstab {
            setup_data.push(
                fdt::create_fdt(android_fstab, dump_device_tree_blob).map_err(Error::CreateFdt)?,
            );
        }
        setup_data.push(setup_data_rng_seed());

        let setup_data = write_setup_data(
            mem,
            GuestAddress(SETUP_DATA_START),
            GuestAddress(SETUP_DATA_END),
            &setup_data,
        )?;

        let initrd = match initrd_file {
            Some(mut initrd_file) => {
                let mut initrd_addr_max = u64::from(params.hdr.initrd_addr_max);
                // Default initrd_addr_max for old kernels (see Documentation/x86/boot.txt).
                if initrd_addr_max == 0 {
                    initrd_addr_max = 0x37FFFFFF;
                }

                let mem_max = mem.end_addr().offset() - 1;
                if initrd_addr_max > mem_max {
                    initrd_addr_max = mem_max;
                }

                let (initrd_start, initrd_size) = arch::load_image_high(
                    mem,
                    &mut initrd_file,
                    GuestAddress(kernel_end),
                    GuestAddress(initrd_addr_max),
                    base::pagesize() as u64,
                )
                .map_err(Error::LoadInitrd)?;
                Some((initrd_start, initrd_size))
            }
            None => None,
        };

        configure_system(
            mem,
            GuestAddress(KERNEL_START_OFFSET),
            GuestAddress(CMDLINE_OFFSET),
            cmdline.to_bytes().len() + 1,
            setup_data,
            initrd,
            params,
        )?;
        Ok(())
    }

    fn get_pcie_vcfg_mmio_range(mem: &GuestMemory, pcie_cfg_mmio: &AddressRange) -> AddressRange {
        // Put PCIe VCFG region at a 2MB boundary after physical memory or 4gb, whichever is greater.
        let ram_end_round_2mb = (mem.end_addr().offset() + 2 * MB - 1) / (2 * MB) * (2 * MB);
        let start = std::cmp::max(ram_end_round_2mb, 4 * GB);
        // Each pci device's ECAM size is 4kb and its vcfg size is 8kb
        let end = start + pcie_cfg_mmio.len().unwrap() * 2 - 1;
        AddressRange { start, end }
    }

    /// Returns the high mmio range
    fn get_high_mmio_range<V: Vm>(vm: &V) -> AddressRange {
        let mem = vm.get_memory();
        let start = Self::get_pcie_vcfg_mmio_range(mem, &read_pcie_cfg_mmio()).end + 1;

        let phys_mem_end = (1u64 << vm.get_guest_phys_addr_bits()) - 1;
        let high_mmio_end = std::cmp::min(phys_mem_end, HIGH_MMIO_MAX_END);

        AddressRange {
            start,
            end: high_mmio_end,
        }
    }

    /// This returns a minimal kernel command for this architecture
    pub fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE as usize);
        cmdline.insert_str("panic=-1").unwrap();

        cmdline
    }

    /// Sets up fw_cfg device. Currently creates an fw_cfg with no slots, so nothing can be
    /// inserted into it.
    ///  # Arguments
    ///
    /// * - `io_bus` - the IO bus object
    /// * - `fw_cfg_parameters` - command-line specified data to add to device. May contain
    /// all None fields if user did not specify data to add to the device
    fn setup_fw_cfg_device(
        io_bus: &devices::Bus,
        fw_cfg_parameters: Vec<FwCfgParameters>,
    ) -> Result<()> {
        // Create fw_cfg device w/ 0 file slots.
        let fw_cfg = Arc::new(Mutex::new(devices::FwCfgDevice::new(0, fw_cfg_parameters)));
        io_bus.insert(fw_cfg, 0x510, 0x4).unwrap();
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
        io_bus: &devices::Bus,
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
        io_bus: &devices::Bus,
        irq_chip: &mut dyn IrqChipX86_64,
        vm_control: Tube,
        mem_size: u64,
    ) -> anyhow::Result<()> {
        let mem_regions = arch_memory_regions(mem_size, None);

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
    /// * - `io_bus` the I/O bus to add the devices to
    /// * - `resources` the SystemAllocator to allocate IO and MMIO for acpi
    ///                devices.
    /// * - `suspend_evt` the event object which used to suspend the vm
    /// * - `sdts` ACPI system description tables
    /// * - `irq_chip` the IrqChip object for registering irq events
    /// * - `battery` indicate whether to create the battery
    /// * - `mmio_bus` the MMIO bus to add the devices to
    pub fn setup_acpi_devices(
        pci_root: Arc<Mutex<PciRoot>>,
        mem: &GuestMemory,
        io_bus: &devices::Bus,
        resources: &mut SystemAllocator,
        suspend_evt: Event,
        vm_evt_wrtube: SendTube,
        sdts: Vec<SDT>,
        #[cfg(feature = "direct")] direct_gpe: &[u32],
        #[cfg(feature = "direct")] direct_fixed_evts: &[devices::ACPIPMFixedEvent],
        irq_chip: &mut dyn IrqChip,
        sci_irq: u32,
        battery: (Option<BatteryType>, Option<Minijail>),
        #[cfg_attr(windows, allow(unused_variables))] mmio_bus: &devices::Bus,
        max_bus: u8,
        resume_notify_devices: &mut Vec<Arc<Mutex<dyn BusResumeDevice>>>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        #[cfg(unix)] ac_adapter: bool,
        #[cfg(unix)] guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) -> Result<(acpi::AcpiDevResource, Option<BatControl>)> {
        // The AML data for the acpi devices
        let mut amls = Vec::new();

        let bat_control = if let Some(battery_type) = battery.0 {
            match battery_type {
                #[cfg(unix)]
                BatteryType::Goldfish => {
                    let irq_num = resources.allocate_irq().ok_or(Error::CreateBatDevices(
                        arch::DeviceRegistrationError::AllocateIrq,
                    ))?;
                    let (control_tube, _mmio_base) = arch::sys::unix::add_goldfish_battery(
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
            &Self::get_pcie_vcfg_mmio_range(mem, &read_pcie_cfg_mmio()).start,
        );
        pcie_vcfg.to_aml_bytes(&mut amls);

        #[cfg(feature = "direct")]
        let direct_evt_info = if direct_gpe.is_empty() && direct_fixed_evts.is_empty() {
            None
        } else {
            let direct_sci_evt = devices::IrqLevelEvent::new().map_err(Error::CreateEvent)?;
            let mut sci_devirq =
                devices::DirectIrq::new_level(&direct_sci_evt).map_err(Error::EnableAcpiEvent)?;

            sci_devirq
                .sci_irq_prepare()
                .map_err(Error::EnableAcpiEvent)?;

            for gpe in direct_gpe {
                sci_devirq
                    .gpe_enable_forwarding(*gpe)
                    .map_err(Error::EnableAcpiEvent)?;
            }

            for evt in direct_fixed_evts {
                sci_devirq
                    .fixed_event_enable_forwarding(*evt)
                    .map_err(Error::EnableAcpiEvent)?;
            }

            Some((direct_sci_evt, direct_gpe, direct_fixed_evts))
        };

        let pm_sci_evt = devices::IrqLevelEvent::new().map_err(Error::CreateEvent)?;

        #[cfg(unix)]
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
        #[cfg(unix)]
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
            #[cfg(feature = "direct")]
            direct_evt_info,
            suspend_evt,
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
            ],
        )
        .to_aml_bytes(&mut amls);

        let root_bus = pci_root.lock().get_root_bus();
        let addresses = root_bus.lock().get_downstream_devices();
        for address in addresses {
            if let Some(acpi_path) = pci_root.lock().acpi_path(&address) {
                aml::Device::new(
                    (*acpi_path).into(),
                    vec![&aml::Name::new("_ADR".into(), &address.acpi_adr())],
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

    /// Sets up the serial devices for this platform. Returns the serial port number and serial
    /// device to be used for stdout
    ///
    /// # Arguments
    ///
    /// * - `irq_chip` the IrqChip object for registering irq events
    /// * - `io_bus` the I/O bus to add the devices to
    /// * - `serial_parmaters` - definitions for how the serial devices should be configured
    pub fn setup_serial_devices(
        protection_type: ProtectionType,
        irq_chip: &mut dyn IrqChip,
        io_bus: &devices::Bus,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
    ) -> Result<()> {
        let com_evt_1_3 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = devices::IrqEdgeEvent::new().map_err(Error::CreateEvent)?;

        arch::add_serial_devices(
            protection_type,
            io_bus,
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
            .register_edge_irq_event(X86_64_SERIAL_1_3_IRQ, &com_evt_1_3, source.clone())
            .map_err(Error::RegisterIrqfd)?;
        irq_chip
            .register_edge_irq_event(X86_64_SERIAL_2_4_IRQ, &com_evt_2_4, source)
            .map_err(Error::RegisterIrqfd)?;

        Ok(())
    }

    fn setup_debugcon_devices(
        protection_type: ProtectionType,
        io_bus: &devices::Bus,
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
                #[cfg(unix)]
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

fn insert_msr(
    msr_map: &mut BTreeMap<u32, MsrConfig>,
    key: u32,
    msr_config: MsrConfig,
) -> std::result::Result<(), MsrError> {
    if msr_map.insert(key, msr_config).is_some() {
        Err(MsrError::MsrDuplicate(key))
    } else {
        Ok(())
    }
}

fn insert_msrs(
    msr_map: &mut BTreeMap<u32, MsrConfig>,
    msrs: &[(u32, MsrRWType, MsrAction, MsrValueFrom, MsrFilter)],
) -> std::result::Result<(), MsrError> {
    for msr in msrs {
        insert_msr(
            msr_map,
            msr.0,
            MsrConfig {
                rw_type: msr.1,
                action: msr.2,
                from: msr.3,
                filter: msr.4,
            },
        )?;
    }

    Ok(())
}

pub fn set_enable_pnp_data_msr_config(
    msr_map: &mut BTreeMap<u32, MsrConfig>,
) -> std::result::Result<(), MsrError> {
    let msrs = vec![
        (
            MSR_IA32_APERF,
            MsrRWType::ReadOnly,
            MsrAction::MsrPassthrough,
            MsrValueFrom::RWFromRunningCPU,
            MsrFilter::Default,
        ),
        (
            MSR_IA32_MPERF,
            MsrRWType::ReadOnly,
            MsrAction::MsrPassthrough,
            MsrValueFrom::RWFromRunningCPU,
            MsrFilter::Default,
        ),
    ];

    insert_msrs(msr_map, &msrs)?;

    Ok(())
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
///     2. Check if CPUID.07H.00H:EDX[bit 15] sets. This bit means the processor is
///        identified as a hybrid part.
///     3. Check if CPUID.1AH:EAX sets. The hybrid core type is set in EAX.
///
/// # Arguments
///
/// * - `cpuid` the wrapped cpuid functions used to get CPUID info.
pub fn check_host_hybrid_support(cpuid: &CpuIdCall) -> std::result::Result<(), HybridSupportError> {
    // CPUID.0H.EAX returns maximum input value for basic CPUID information.
    //
    // Safe because we pass 0 for this call and the host supports the
    // `cpuid` instruction.
    let mut cpuid_entry = unsafe { (cpuid.cpuid)(0x0) };
    if cpuid_entry.eax < 0x1A {
        return Err(HybridSupportError::UnsupportedHostCpu);
    }
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

    const TEST_MEMORY_SIZE: u64 = 2 * GB;

    fn setup() {
        let pcie_ecam = Some(AddressRange::from_start_and_size(3 * GB, 256 * MB).unwrap());
        let pci_start = Some(2 * GB);
        init_low_memory_layout(pcie_ecam, pci_start);
    }

    #[test]
    fn regions_lt_4gb_nobios() {
        setup();
        let regions = arch_memory_regions(512 * MB, /* bios_size */ None);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(1u64 << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb_nobios() {
        setup();
        let size = 4 * GB + 0x8000;
        let regions = arch_memory_regions(size, /* bios_size */ None);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(GuestAddress(4 * GB), regions[1].0);
        assert_eq!(4 * GB + 0x8000, regions[0].1 + regions[1].1);
    }

    #[test]
    fn regions_lt_4gb_bios() {
        setup();
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(512 * MB, Some(bios_len));
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(512 * MB, regions[0].1);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
    }

    #[test]
    fn regions_gt_4gb_bios() {
        setup();
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(4 * GB + 0x8000, Some(bios_len));
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
        assert_eq!(GuestAddress(4 * GB), regions[2].0);
    }

    #[test]
    fn regions_eq_4gb_nobios() {
        setup();
        // Test with exact size of 4GB - the overhead.
        let regions = arch_memory_regions(
            TEST_MEMORY_SIZE - START_OF_RAM_32BITS,
            /* bios_size */ None,
        );
        dbg!(&regions);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(TEST_MEMORY_SIZE - START_OF_RAM_32BITS, regions[0].1);
    }

    #[test]
    fn regions_eq_4gb_bios() {
        setup();
        // Test with exact size of 4GB - the overhead.
        let bios_len = 1 * MB;
        let regions = arch_memory_regions(TEST_MEMORY_SIZE - START_OF_RAM_32BITS, Some(bios_len));
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(START_OF_RAM_32BITS), regions[0].0);
        assert_eq!(TEST_MEMORY_SIZE - START_OF_RAM_32BITS, regions[0].1);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
    }

    #[test]
    fn check_pci_mmio_layout() {
        setup();

        assert_eq!(read_pci_mmio_before_32bit().start, 2 * GB);
        assert_eq!(read_pcie_cfg_mmio().start, 3 * GB);
        assert_eq!(read_pcie_cfg_mmio().len().unwrap(), 256 * MB);
    }

    #[test]
    fn check_32bit_gap_size_alignment() {
        setup();
        // pci_low_start is 256 MB aligned to be friendly for MTRR mappings.
        assert_eq!(read_pci_mmio_before_32bit().start % (256 * MB), 0);
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
}
