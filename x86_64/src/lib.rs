// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod fdt;

const E820_RAM: u32 = 1;
const SETUP_DTB: u32 = 2;
const X86_64_FDT_MAX_SIZE: u64 = 0x200000;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bootparam;

// boot_params is just a series of ints, it is safe to initialize it.
unsafe impl data_model::DataInit for bootparam::boot_params {}

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(clippy::all)]
mod mpspec;
// These mpspec types are only data, reading them from data is a safe initialization.
unsafe impl data_model::DataInit for mpspec::mpc_bus {}
unsafe impl data_model::DataInit for mpspec::mpc_cpu {}
unsafe impl data_model::DataInit for mpspec::mpc_intsrc {}
unsafe impl data_model::DataInit for mpspec::mpc_ioapic {}
unsafe impl data_model::DataInit for mpspec::mpc_table {}
unsafe impl data_model::DataInit for mpspec::mpc_lintsrc {}
unsafe impl data_model::DataInit for mpspec::mpf_intel {}

mod acpi;
mod bzimage;
mod cpuid;
mod gdt;
mod interrupts;
mod mptable;
mod regs;
mod smbios;

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Seek};
use std::mem;
use std::sync::Arc;

use crate::bootparam::boot_params;
use acpi_tables::aml::Aml;
use acpi_tables::sdt::SDT;
use arch::{
    get_serial_cmdline, GetSerialCmdlineError, RunnableLinuxVm, SerialHardware, SerialParameters,
    VmComponents, VmImage,
};
use base::Event;
use devices::{IrqChip, IrqChipX86_64, PciConfigIo, PciDevice, ProtectionType};
use hypervisor::{HypervisorX86_64, VcpuX86_64, VmX86_64};
use minijail::Minijail;
use remain::sorted;
use resources::SystemAllocator;
use sync::Mutex;
use vm_control::{BatControl, BatteryType};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use {
    gdbstub::arch::x86::reg::X86_64CoreRegs,
    hypervisor::x86_64::{Regs, Sregs},
};

#[sorted]
#[derive(Debug)]
pub enum Error {
    AllocateIOResouce(resources::Error),
    AllocateIrq,
    CloneEvent(base::Error),
    Cmdline(kernel_cmdline::Error),
    ConfigureSystem,
    CreateBatDevices(arch::DeviceRegistrationError),
    CreateDevices(Box<dyn StdError>),
    CreateEvent(base::Error),
    CreateFdt(arch::fdt::Error),
    CreateIoapicDevice(base::Error),
    CreateIrqChip(Box<dyn StdError>),
    CreatePciRoot(arch::DeviceRegistrationError),
    CreatePit(base::Error),
    CreatePitDevice(devices::PitError),
    CreateSerialDevices(arch::DeviceRegistrationError),
    CreateSocket(io::Error),
    CreateVcpu(base::Error),
    CreateVm(Box<dyn StdError>),
    E820Configuration,
    EnableSinglestep(base::Error),
    EnableSplitIrqchip(base::Error),
    GetSerialCmdline(GetSerialCmdlineError),
    KernelOffsetPastEnd,
    LoadBios(io::Error),
    LoadBzImage(bzimage::Error),
    LoadCmdline(kernel_loader::Error),
    LoadInitrd(arch::LoadImageError),
    LoadKernel(kernel_loader::Error),
    PageNotPresent,
    Pstore(arch::pstore::Error),
    ReadingGuestMemory(vm_memory::GuestMemoryError),
    ReadRegs(base::Error),
    RegisterIrqfd(base::Error),
    RegisterVsock(arch::DeviceRegistrationError),
    SetHwBreakpoint(base::Error),
    SetLint(interrupts::Error),
    SetTssAddr(base::Error),
    SetupCpuid(cpuid::Error),
    SetupFpu(regs::Error),
    SetupGuestMemory(GuestMemoryError),
    SetupMptable(mptable::Error),
    SetupMsrs(regs::Error),
    SetupRegs(regs::Error),
    SetupSmbios(smbios::Error),
    SetupSregs(regs::Error),
    TranslatingVirtAddr,
    UnsupportedProtectionType,
    WriteRegs(base::Error),
    WritingGuestMemory(GuestMemoryError),
    ZeroPagePastRamEnd,
    ZeroPageSetup,
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            AllocateIOResouce(e) => write!(f, "error allocating IO resource: {}", e),
            AllocateIrq => write!(f, "error allocating a single irq"),
            CloneEvent(e) => write!(f, "unable to clone an Event: {}", e),
            Cmdline(e) => write!(f, "the given kernel command line was invalid: {}", e),
            ConfigureSystem => write!(f, "error configuring the system"),
            CreateBatDevices(e) => write!(f, "unable to create battery devices: {}", e),
            CreateDevices(e) => write!(f, "error creating devices: {}", e),
            CreateEvent(e) => write!(f, "unable to make an Event: {}", e),
            CreateFdt(e) => write!(f, "failed to create fdt: {}", e),
            CreateIoapicDevice(e) => write!(f, "failed to create IOAPIC device: {}", e),
            CreateIrqChip(e) => write!(f, "failed to create IRQ chip: {}", e),
            CreatePciRoot(e) => write!(f, "failed to create a PCI root hub: {}", e),
            CreatePit(e) => write!(f, "unable to create PIT: {}", e),
            CreatePitDevice(e) => write!(f, "unable to make PIT device: {}", e),
            CreateSerialDevices(e) => write!(f, "unable to create serial devices: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateVcpu(e) => write!(f, "failed to create VCPU: {}", e),
            CreateVm(e) => write!(f, "failed to create VM: {}", e),
            E820Configuration => write!(f, "invalid e820 setup params"),
            EnableSinglestep(e) => write!(f, "failed to enable singlestep execution: {}", e),
            EnableSplitIrqchip(e) => write!(f, "failed to enable split irqchip: {}", e),
            GetSerialCmdline(e) => write!(f, "failed to get serial cmdline: {}", e),
            KernelOffsetPastEnd => write!(f, "the kernel extends past the end of RAM"),
            LoadBios(e) => write!(f, "error loading bios: {}", e),
            LoadBzImage(e) => write!(f, "error loading kernel bzImage: {}", e),
            LoadCmdline(e) => write!(f, "error loading command line: {}", e),
            LoadInitrd(e) => write!(f, "error loading initrd: {}", e),
            LoadKernel(e) => write!(f, "error loading Kernel: {}", e),
            PageNotPresent => write!(f, "error translating address: Page not present"),
            Pstore(e) => write!(f, "failed to allocate pstore region: {}", e),
            ReadingGuestMemory(e) => write!(f, "error reading guest memory {}", e),
            ReadRegs(e) => write!(f, "error reading CPU registers {}", e),
            RegisterIrqfd(e) => write!(f, "error registering an IrqFd: {}", e),
            RegisterVsock(e) => write!(f, "error registering virtual socket device: {}", e),
            SetHwBreakpoint(e) => write!(f, "failed to set a hardware breakpoint: {}", e),
            SetLint(e) => write!(f, "failed to set interrupts: {}", e),
            SetTssAddr(e) => write!(f, "failed to set tss addr: {}", e),
            SetupCpuid(e) => write!(f, "failed to set up cpuid: {}", e),
            SetupFpu(e) => write!(f, "failed to set up FPU: {}", e),
            SetupGuestMemory(e) => write!(f, "failed to set up guest memory: {}", e),
            SetupMptable(e) => write!(f, "failed to set up mptable: {}", e),
            SetupMsrs(e) => write!(f, "failed to set up MSRs: {}", e),
            SetupRegs(e) => write!(f, "failed to set up registers: {}", e),
            SetupSmbios(e) => write!(f, "failed to set up SMBIOS: {}", e),
            SetupSregs(e) => write!(f, "failed to set up sregs: {}", e),
            TranslatingVirtAddr => write!(f, "failed to translate virtual address"),
            UnsupportedProtectionType => write!(f, "protected VMs not supported on x86_64"),
            WriteRegs(e) => write!(f, "error writing CPU registers {}", e),
            WritingGuestMemory(e) => write!(f, "error writing guest memory {}", e),
            ZeroPagePastRamEnd => write!(f, "the zero page extends past the end of guest_mem"),
            ZeroPageSetup => write!(f, "error writing the zero page of guest memory"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

pub struct X8664arch;

const BOOT_STACK_POINTER: u64 = 0x8000;
// Make sure it align to 256MB for MTRR convenient
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
const END_ADDR_BEFORE_32BITS: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
const MMIO_SIZE: u64 = MEM_32BIT_GAP_SIZE - 0x8000000;
const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;
const ZERO_PAGE_OFFSET: u64 = 0x7000;
const TSS_ADDR: u64 = 0xfffbd000;

const KERNEL_START_OFFSET: u64 = 0x200000;
const CMDLINE_OFFSET: u64 = 0x20000;
const CMDLINE_MAX_SIZE: u64 = KERNEL_START_OFFSET - CMDLINE_OFFSET;
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
const ACPI_HI_RSDP_WINDOW_BASE: u64 = 0x000E0000;

/// The x86 reset vector for i386+ and x86_64 puts the processor into an "unreal mode" where it
/// can access the last 1 MB of the 32-bit address space in 16-bit mode, and starts the instruction
/// pointer at the effective physical address 0xFFFFFFF0.
fn bios_start(bios_size: u64) -> GuestAddress {
    GuestAddress(FIRST_ADDR_PAST_32BITS - bios_size)
}

fn configure_system(
    guest_mem: &GuestMemory,
    _mem_size: u64,
    kernel_addr: GuestAddress,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    setup_data: Option<GuestAddress>,
    initrd: Option<(GuestAddress, usize)>,
    mut params: boot_params,
) -> Result<()> {
    const EBDA_START: u64 = 0x0009fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(END_ADDR_BEFORE_32BITS);

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(setup_data) = setup_data {
        params.hdr.setup_data = setup_data.offset();
    }
    if let Some((initrd_addr, initrd_size)) = initrd {
        params.hdr.ramdisk_image = initrd_addr.offset() as u32;
        params.hdr.ramdisk_size = initrd_size as u32;
    }

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            kernel_addr.offset() as u64,
            mem_end.offset_from(kernel_addr) as u64,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            kernel_addr.offset() as u64,
            end_32bit_gap_start.offset_from(kernel_addr) as u64,
            E820_RAM,
        )?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.offset() as u64,
                mem_end.offset_from(first_addr_past_32bits) as u64,
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(ZERO_PAGE_OFFSET);
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>() as u64)
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
fn arch_memory_regions(size: u64, bios_size: Option<u64>) -> Vec<(GuestAddress, u64)> {
    let mem_end = GuestAddress(size);
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(END_ADDR_BEFORE_32BITS);

    let mut regions = Vec::new();
    if mem_end <= end_32bit_gap_start {
        regions.push((GuestAddress(0), size));
        if let Some(bios_size) = bios_size {
            regions.push((bios_start(bios_size), bios_size));
        }
    } else {
        regions.push((GuestAddress(0), end_32bit_gap_start.offset()));
        if let Some(bios_size) = bios_size {
            regions.push((bios_start(bios_size), bios_size));
        }
        regions.push((
            first_addr_past_32bits,
            mem_end.offset_from(end_32bit_gap_start),
        ));
    }

    regions
}

impl arch::LinuxArch for X8664arch {
    type Error = Error;

    fn guest_memory_layout(
        components: &VmComponents,
    ) -> std::result::Result<Vec<(GuestAddress, u64)>, Self::Error> {
        let bios_size = match &components.vm_image {
            VmImage::Bios(bios_file) => Some(bios_file.metadata().map_err(Error::LoadBios)?.len()),
            VmImage::Kernel(_) => None,
        };
        Ok(arch_memory_regions(components.memory_size, bios_size))
    }

    fn build_vm<V, Vcpu, I, FD, FI, E1, E2>(
        mut components: VmComponents,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        battery: (&Option<BatteryType>, Option<Minijail>),
        mut vm: V,
        create_devices: FD,
        create_irq_chip: FI,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu, I>, Self::Error>
    where
        V: VmX86_64,
        Vcpu: VcpuX86_64,
        I: IrqChipX86_64,
        FD: FnOnce(
            &GuestMemory,
            &mut V,
            &mut SystemAllocator,
            &Event,
        ) -> std::result::Result<Vec<(Box<dyn PciDevice>, Option<Minijail>)>, E1>,
        FI: FnOnce(&V, /* vcpu_count: */ usize) -> std::result::Result<I, E2>,
        E1: StdError + 'static,
        E2: StdError + 'static,
    {
        if components.protected_vm != ProtectionType::Unprotected {
            return Err(Error::UnsupportedProtectionType);
        }

        let mem = vm.get_memory().clone();
        let mut resources = Self::get_resource_allocator(&mem);

        let vcpu_count = components.vcpu_count;
        let mut irq_chip =
            create_irq_chip(&vm, vcpu_count).map_err(|e| Error::CreateIrqChip(Box::new(e)))?;

        let tss_addr = GuestAddress(TSS_ADDR);
        vm.set_tss_addr(tss_addr).map_err(Error::SetTssAddr)?;

        let mut mmio_bus = devices::Bus::new();

        let exit_evt = Event::new().map_err(Error::CreateEvent)?;

        let pci_devices = create_devices(&mem, &mut vm, &mut resources, &exit_evt)
            .map_err(|e| Error::CreateDevices(Box::new(e)))?;
        let (pci, pci_irqs, pid_debug_label_map) = arch::generate_pci_root(
            pci_devices,
            &mut irq_chip,
            &mut mmio_bus,
            &mut resources,
            &mut vm,
            4, // Share the four pin interrupts (INTx#)
        )
        .map_err(Error::CreatePciRoot)?;
        let pci_bus = Arc::new(Mutex::new(PciConfigIo::new(pci)));

        // Event used to notify crosvm that guest OS is trying to suspend.
        let suspend_evt = Event::new().map_err(Error::CreateEvent)?;

        let mut io_bus = Self::setup_io_bus(
            irq_chip.pit_uses_speaker_port(),
            exit_evt.try_clone().map_err(Error::CloneEvent)?,
            Some(pci_bus),
            components.memory_size,
        )?;

        Self::setup_serial_devices(
            components.protected_vm,
            &mut irq_chip,
            &mut io_bus,
            serial_parameters,
            serial_jail,
        )?;

        let (acpi_dev_resource, bat_control) = Self::setup_acpi_devices(
            &mut io_bus,
            &mut resources,
            suspend_evt.try_clone().map_err(Error::CloneEvent)?,
            exit_evt.try_clone().map_err(Error::CloneEvent)?,
            components.acpi_sdts,
            &mut irq_chip,
            battery,
            &mut mmio_bus,
        )?;

        let ramoops_region = match components.pstore {
            Some(pstore) => Some(
                arch::pstore::create_memory_region(&mut vm, &mut resources, &pstore)
                    .map_err(Error::Pstore)?,
            ),
            None => None,
        };

        irq_chip
            .finalize_devices(&mut resources, &mut io_bus, &mut mmio_bus)
            .map_err(Error::RegisterIrqfd)?;

        // All of these bios generated tables are set manually for the benefit of the kernel boot
        // flow (since there's no BIOS to set it) and for the BIOS boot flow since crosvm doesn't
        // have a way to pass the BIOS these configs.
        // This works right now because the only guest BIOS used with crosvm (u-boot) ignores these
        // tables and the guest OS picks them up.
        // If another guest does need a way to pass these tables down to it's BIOS, this approach
        // should be rethought.

        // Note that this puts the mptable at 0x9FC00 in guest physical memory.
        mptable::setup_mptable(&mem, vcpu_count as u8, pci_irqs).map_err(Error::SetupMptable)?;
        smbios::setup_smbios(&mem, components.dmi_path).map_err(Error::SetupSmbios)?;

        // TODO (tjeznach) Write RSDP to bootconfig before writing to memory
        acpi::create_acpi_tables(&mem, vcpu_count as u8, X86_64_SCI_IRQ, acpi_dev_resource);

        match components.vm_image {
            VmImage::Bios(ref mut bios) => Self::load_bios(&mem, bios)?,
            VmImage::Kernel(ref mut kernel_image) => {
                let mut cmdline = Self::get_base_linux_cmdline();

                get_serial_cmdline(&mut cmdline, serial_parameters, "io")
                    .map_err(Error::GetSerialCmdline)?;

                for param in components.extra_kernel_params {
                    cmdline.insert_str(&param).map_err(Error::Cmdline)?;
                }
                // It seems that default record_size is only 4096 byte even if crosvm allocates
                // more memory. It means that one crash can only 4096 byte.
                // Set record_size and console_size to 1/4 of allocated memory size.
                // This configulation is same as the host.
                if let Some(ramoops_region) = ramoops_region {
                    let ramoops_opts = [
                        ("mem_address", ramoops_region.address),
                        ("mem_size", ramoops_region.size as u64),
                        ("console_size", (ramoops_region.size / 4) as u64),
                        ("record_size", (ramoops_region.size / 4) as u64),
                        ("dump_oops", 1_u64),
                    ];
                    for (name, val) in &ramoops_opts {
                        cmdline
                            .insert_str(format!("ramoops.{}={:#x}", name, val))
                            .map_err(Error::Cmdline)?;
                    }
                }

                // separate out load_kernel from other setup to get a specific error for
                // kernel loading
                let (params, kernel_end) = Self::load_kernel(&mem, kernel_image)?;

                Self::setup_system_memory(
                    &mem,
                    components.memory_size,
                    &CString::new(cmdline).unwrap(),
                    components.initrd_image,
                    components.android_fstab,
                    kernel_end,
                    params,
                )?;
            }
        }

        Ok(RunnableLinuxVm {
            vm,
            resources,
            exit_evt,
            vcpu_count,
            vcpus: None,
            vcpu_affinity: components.vcpu_affinity,
            no_smt: components.no_smt,
            irq_chip,
            has_bios: matches!(components.vm_image, VmImage::Bios(_)),
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            suspend_evt,
            rt_cpus: components.rt_cpus,
            bat_control,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            gdb: components.gdb,
        })
    }

    fn configure_vcpu(
        guest_mem: &GuestMemory,
        hypervisor: &dyn HypervisorX86_64,
        irq_chip: &mut dyn IrqChipX86_64,
        vcpu: &mut dyn VcpuX86_64,
        vcpu_id: usize,
        num_cpus: usize,
        has_bios: bool,
        no_smt: bool,
    ) -> Result<()> {
        cpuid::setup_cpuid(hypervisor, irq_chip, vcpu, vcpu_id, num_cpus, no_smt)
            .map_err(Error::SetupCpuid)?;

        if has_bios {
            return Ok(());
        }

        let kernel_load_addr = GuestAddress(KERNEL_START_OFFSET);
        regs::setup_msrs(vcpu, END_ADDR_BEFORE_32BITS).map_err(Error::SetupMsrs)?;
        let kernel_end = guest_mem
            .checked_offset(kernel_load_addr, KERNEL_64BIT_ENTRY_OFFSET)
            .ok_or(Error::KernelOffsetPastEnd)?;
        regs::setup_regs(
            vcpu,
            (kernel_end).offset() as u64,
            BOOT_STACK_POINTER as u64,
            ZERO_PAGE_OFFSET as u64,
        )
        .map_err(Error::SetupRegs)?;
        regs::setup_fpu(vcpu).map_err(Error::SetupFpu)?;
        regs::setup_sregs(guest_mem, vcpu).map_err(Error::SetupSregs)?;
        interrupts::set_lint(vcpu_id, irq_chip).map_err(Error::SetLint)?;

        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_read_registers<T: VcpuX86_64>(vcpu: &T) -> Result<X86_64CoreRegs> {
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
        let sgs = [sregs.cs, sregs.ss, sregs.ds, sregs.es, sregs.fs, sregs.gs];
        let mut segments = [0u32; 6];
        // GDB uses only the selectors.
        for i in 0..sgs.len() {
            segments[i] = sgs[i].selector as u32;
        }

        // TODO(keiichiw): Other registers such as FPU, xmm and mxcsr.

        Ok(X86_64CoreRegs {
            regs,
            eflags,
            rip,
            segments,
            ..Default::default()
        })
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_write_registers<T: VcpuX86_64>(vcpu: &T, regs: &X86_64CoreRegs) -> Result<()> {
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
        sregs.cs.selector = regs.segments[0] as u16;
        sregs.ss.selector = regs.segments[1] as u16;
        sregs.ds.selector = regs.segments[2] as u16;
        sregs.es.selector = regs.segments[3] as u16;
        sregs.fs.selector = regs.segments[4] as u16;
        sregs.gs.selector = regs.segments[5] as u16;

        vcpu.set_sregs(&sregs).map_err(Error::WriteRegs)?;

        // TODO(keiichiw): Other registers such as FPU, xmm and mxcsr.

        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_read_memory<T: VcpuX86_64>(
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

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_write_memory<T: VcpuX86_64>(
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

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_enable_singlestep<T: VcpuX86_64>(vcpu: &T) -> Result<()> {
        vcpu.set_guest_debug(&[], true /* enable_singlestep */)
            .map_err(Error::EnableSinglestep)
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    fn debug_set_hw_breakpoints<T: VcpuX86_64>(
        vcpu: &T,
        breakpoints: &[GuestAddress],
    ) -> Result<()> {
        vcpu.set_guest_debug(&breakpoints, false /* enable_singlestep */)
            .map_err(Error::SetHwBreakpoint)
    }
}

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
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

    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    fn load_kernel(mem: &GuestMemory, kernel_image: &mut File) -> Result<(boot_params, u64)> {
        let elf_result =
            kernel_loader::load_kernel(mem, GuestAddress(KERNEL_START_OFFSET), kernel_image);
        if elf_result == Err(kernel_loader::Error::InvalidElfMagicNumber) {
            bzimage::load_bzimage(mem, GuestAddress(KERNEL_START_OFFSET), kernel_image)
                .map_err(Error::LoadBzImage)
        } else {
            let kernel_end = elf_result.map_err(Error::LoadKernel)?;
            Ok((Default::default(), kernel_end))
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
    fn setup_system_memory(
        mem: &GuestMemory,
        mem_size: u64,
        cmdline: &CStr,
        initrd_file: Option<File>,
        android_fstab: Option<File>,
        kernel_end: u64,
        params: boot_params,
    ) -> Result<()> {
        kernel_loader::load_cmdline(mem, GuestAddress(CMDLINE_OFFSET), cmdline)
            .map_err(Error::LoadCmdline)?;

        // Track the first free address after the kernel - this is where extra
        // data like the device tree blob and initrd will be loaded.
        let mut free_addr = kernel_end;

        let setup_data = if let Some(android_fstab) = android_fstab {
            let free_addr_aligned = (((free_addr + 64 - 1) / 64) * 64) + 64;
            let dtb_start = GuestAddress(free_addr_aligned);
            let dtb_size = fdt::create_fdt(
                X86_64_FDT_MAX_SIZE as usize,
                mem,
                dtb_start.offset(),
                android_fstab,
            )
            .map_err(Error::CreateFdt)?;
            free_addr = dtb_start.offset() + dtb_size as u64;
            Some(dtb_start)
        } else {
            None
        };

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
                    GuestAddress(free_addr),
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
            mem_size,
            GuestAddress(KERNEL_START_OFFSET),
            GuestAddress(CMDLINE_OFFSET),
            cmdline.to_bytes().len() + 1,
            setup_data,
            initrd,
            params,
        )?;
        Ok(())
    }

    /// This returns the start address of high mmio
    ///
    /// # Arguments
    ///
    /// * mem: The memory to be used by the guest
    fn get_high_mmio_base(mem: &GuestMemory) -> u64 {
        // Put device memory at a 2MB boundary after physical memory or 4gb, whichever is greater.
        const MB: u64 = 1 << 20;
        const GB: u64 = 1 << 30;
        let ram_end_round_2mb = (mem.end_addr().offset() + 2 * MB - 1) / (2 * MB) * (2 * MB);
        std::cmp::max(ram_end_round_2mb, 4 * GB)
    }

    /// This returns a minimal kernel command for this architecture
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE as usize);
        cmdline.insert_str("pci=noacpi reboot=k panic=-1").unwrap();

        cmdline
    }

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem: &GuestMemory) -> SystemAllocator {
        let high_mmio_start = Self::get_high_mmio_base(mem);
        SystemAllocator::builder()
            .add_io_addresses(0xc000, 0x10000)
            .add_low_mmio_addresses(END_ADDR_BEFORE_32BITS, MMIO_SIZE)
            .add_high_mmio_addresses(high_mmio_start, u64::max_value() - high_mmio_start)
            .create_allocator(X86_64_IRQ_BASE)
            .unwrap()
    }

    /// Sets up the IO bus for this platform
    ///
    /// # Arguments
    ///
    /// * - `pit_uses_speaker_port` - does the PIT use port 0x61 for the PC speaker
    /// * - `exit_evt` - the event object which should receive exit events
    /// * - `mem_size` - the size in bytes of physical ram for the guest
    fn setup_io_bus(
        pit_uses_speaker_port: bool,
        exit_evt: Event,
        pci: Option<Arc<Mutex<devices::PciConfigIo>>>,
        mem_size: u64,
    ) -> Result<devices::Bus> {
        struct NoDevice;
        impl devices::BusDevice for NoDevice {
            fn debug_label(&self) -> String {
                "no device".to_owned()
            }
        }

        let mut io_bus = devices::Bus::new();

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

        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Cmos::new(mem_below_4g, mem_above_4g))),
                0x70,
                0x2,
            )
            .unwrap();

        let nul_device = Arc::new(Mutex::new(NoDevice));
        let i8042 = Arc::new(Mutex::new(devices::I8042Device::new(
            exit_evt.try_clone().map_err(Error::CloneEvent)?,
        )));

        if pit_uses_speaker_port {
            io_bus.insert(i8042, 0x062, 0x3).unwrap();
        } else {
            io_bus.insert(i8042, 0x061, 0x4).unwrap();
        }

        io_bus.insert(nul_device.clone(), 0x0ed, 0x1).unwrap(); // most likely this one does nothing
        io_bus.insert(nul_device.clone(), 0x0f0, 0x2).unwrap(); // ignore fpu

        if let Some(pci_root) = pci {
            io_bus.insert(pci_root, 0xcf8, 0x8).unwrap();
        } else {
            // ignore pci.
            io_bus.insert(nul_device, 0xcf8, 0x8).unwrap();
        }

        Ok(io_bus)
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
    fn setup_acpi_devices(
        io_bus: &mut devices::Bus,
        resources: &mut SystemAllocator,
        suspend_evt: Event,
        exit_evt: Event,
        sdts: Vec<SDT>,
        irq_chip: &mut impl IrqChip,
        battery: (&Option<BatteryType>, Option<Minijail>),
        mmio_bus: &mut devices::Bus,
    ) -> Result<(acpi::ACPIDevResource, Option<BatControl>)> {
        // The AML data for the acpi devices
        let mut amls = Vec::new();

        let pm_alloc = resources.get_anon_alloc();
        let pm_iobase = match resources.io_allocator() {
            Some(io) => io
                .allocate_with_align(
                    devices::acpi::ACPIPM_RESOURCE_LEN as u64,
                    pm_alloc,
                    "ACPIPM".to_string(),
                    devices::acpi::ACPIPM_RESOURCE_LEN as u64,
                )
                .map_err(Error::AllocateIOResouce)?,
            None => 0x600,
        };

        let pmresource = devices::ACPIPMResource::new(suspend_evt, exit_evt);
        Aml::to_aml_bytes(&pmresource, &mut amls);
        let pm = Arc::new(Mutex::new(pmresource));
        io_bus
            .insert(
                pm.clone(),
                pm_iobase as u64,
                devices::acpi::ACPIPM_RESOURCE_LEN as u64,
            )
            .unwrap();
        io_bus.notify_on_resume(pm);

        let bat_control = if let Some(battery_type) = battery.0 {
            match battery_type {
                BatteryType::Goldfish => {
                    let control_tube = arch::add_goldfish_battery(
                        &mut amls,
                        battery.1,
                        mmio_bus,
                        irq_chip,
                        X86_64_SCI_IRQ,
                        resources,
                    )
                    .map_err(Error::CreateBatDevices)?;
                    Some(BatControl {
                        type_: BatteryType::Goldfish,
                        control_tube,
                    })
                }
            }
        } else {
            None
        };

        Ok((
            acpi::ACPIDevResource {
                amls,
                pm_iobase,
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
    fn setup_serial_devices(
        protected_vm: ProtectionType,
        irq_chip: &mut impl IrqChip,
        io_bus: &mut devices::Bus,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
    ) -> Result<()> {
        let com_evt_1_3 = Event::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = Event::new().map_err(Error::CreateEvent)?;

        arch::add_serial_devices(
            protected_vm,
            io_bus,
            &com_evt_1_3,
            &com_evt_2_4,
            &serial_parameters,
            serial_jail,
        )
        .map_err(Error::CreateSerialDevices)?;

        irq_chip
            .register_irq_event(X86_64_SERIAL_1_3_IRQ, &com_evt_1_3, None)
            .map_err(Error::RegisterIrqfd)?;
        irq_chip
            .register_irq_event(X86_64_SERIAL_2_4_IRQ, &com_evt_2_4, None)
            .map_err(Error::RegisterIrqfd)?;

        Ok(())
    }
}

#[cfg(test)]
mod test_integration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_lt_4gb_nobios() {
        let regions = arch_memory_regions(1u64 << 29, /* bios_size */ None);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1u64 << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb_nobios() {
        let regions = arch_memory_regions((1u64 << 32) + 0x8000, /* bios_size */ None);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1u64 << 32), regions[1].0);
    }

    #[test]
    fn regions_lt_4gb_bios() {
        let bios_len = 1 << 20;
        let regions = arch_memory_regions(1u64 << 29, Some(bios_len));
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1u64 << 29, regions[0].1);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
    }

    #[test]
    fn regions_gt_4gb_bios() {
        let bios_len = 1 << 20;
        let regions = arch_memory_regions((1u64 << 32) + 0x8000, Some(bios_len));
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
        assert_eq!(GuestAddress(1u64 << 32), regions[2].0);
    }

    #[test]
    fn regions_eq_4gb_nobios() {
        // Test with size = 3328, which is exactly 4 GiB minus the size of the gap (768 MiB).
        let regions = arch_memory_regions(3328 << 20, /* bios_size */ None);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(3328 << 20, regions[0].1);
    }

    #[test]
    fn regions_eq_4gb_bios() {
        // Test with size = 3328, which is exactly 4 GiB minus the size of the gap (768 MiB).
        let bios_len = 1 << 20;
        let regions = arch_memory_regions(3328 << 20, Some(bios_len));
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(3328 << 20, regions[0].1);
        assert_eq!(
            GuestAddress(FIRST_ADDR_PAST_32BITS - bios_len),
            regions[1].0
        );
        assert_eq!(bios_len, regions[1].1);
    }
}
