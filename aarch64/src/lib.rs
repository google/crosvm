// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::sync::Arc;

use arch::{
    get_serial_cmdline, GetSerialCmdlineError, RunnableLinuxVm, SerialHardware, SerialParameters,
    VmComponents, VmImage,
};
use base::Event;
use devices::{
    Bus, BusError, IrqChip, IrqChipAArch64, PciAddress, PciConfigMmio, PciDevice, PciInterruptPin,
};
use hypervisor::{DeviceKind, Hypervisor, HypervisorCap, VcpuAArch64, VcpuFeature, VmAArch64};
use minijail::Minijail;
use remain::sorted;
use resources::SystemAllocator;
use sync::Mutex;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

mod fdt;

// We place the kernel at offset 8MB
const AARCH64_KERNEL_OFFSET: u64 = 0x80000;
const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;
const AARCH64_INITRD_ALIGN: u64 = 0x1000000;

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// This indicates the start of DRAM inside the physical address space.
const AARCH64_PHYS_MEM_START: u64 = 0x80000000;
const AARCH64_AXI_BASE: u64 = 0x40000000;

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

macro_rules! offset__of {
    ($str:ty, $($field:ident).+ $([$idx:expr])*) => {
        unsafe { &(*(0 as *const $str))$(.$field)*  $([$idx])* as *const _ as usize }
    }
}

const KVM_REG_ARM64: u64 = 0x6000000000000000;
const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
const KVM_REG_ARM_COPROC_SHIFT: u64 = 16;
const KVM_REG_ARM_CORE: u64 = 0x0010 << KVM_REG_ARM_COPROC_SHIFT;

macro_rules! arm64_core_reg {
    ($reg: tt) => {
        KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM_CORE
            | ((offset__of!(kvm_sys::user_pt_regs, $reg) / 4) as u64)
    };
}

fn get_kernel_addr() -> GuestAddress {
    GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_KERNEL_OFFSET)
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

// PCI MMIO configuration region base address.
const AARCH64_PCI_CFG_BASE: u64 = 0x10000;
// PCI MMIO configuration region size.
const AARCH64_PCI_CFG_SIZE: u64 = 0x1000000;
// This is the base address of MMIO devices.
const AARCH64_MMIO_BASE: u64 = 0x1010000;
// Size of the whole MMIO region.
const AARCH64_MMIO_SIZE: u64 = 0x100000;
// Virtio devices start at SPI interrupt number 3
const AARCH64_IRQ_BASE: u32 = 3;

// PMU PPI interrupt, same as qemu
const AARCH64_PMU_IRQ: u32 = 7;

#[sorted]
#[derive(Debug)]
pub enum Error {
    CloneEvent(base::Error),
    Cmdline(kernel_cmdline::Error),
    CreateDevices(Box<dyn StdError>),
    CreateEvent(base::Error),
    CreateFdt(arch::fdt::Error),
    CreateGICFailure(base::Error),
    CreateIrqChip(Box<dyn StdError>),
    CreatePciRoot(arch::DeviceRegistrationError),
    CreateSerialDevices(arch::DeviceRegistrationError),
    CreateSocket(io::Error),
    CreateVcpu(base::Error),
    CreateVm(Box<dyn StdError>),
    GetSerialCmdline(GetSerialCmdlineError),
    InitrdLoadFailure(arch::LoadImageError),
    KernelLoadFailure(arch::LoadImageError),
    KernelMissing,
    RegisterIrqfd(base::Error),
    RegisterPci(BusError),
    RegisterVsock(arch::DeviceRegistrationError),
    SetDeviceAttr(base::Error),
    SetReg(base::Error),
    SetupGuestMemory(GuestMemoryError),
    VcpuInit(base::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CloneEvent(e) => write!(f, "unable to clone an Event: {}", e),
            Cmdline(e) => write!(f, "the given kernel command line was invalid: {}", e),
            CreateDevices(e) => write!(f, "error creating devices: {}", e),
            CreateEvent(e) => write!(f, "unable to make an Event: {}", e),
            CreateFdt(e) => write!(f, "FDT could not be created: {}", e),
            CreateGICFailure(e) => write!(f, "failed to create GIC: {}", e),
            CreateIrqChip(e) => write!(f, "failed to create IRQ chip: {}", e),
            CreatePciRoot(e) => write!(f, "failed to create a PCI root hub: {}", e),
            CreateSerialDevices(e) => write!(f, "unable to create serial devices: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateVcpu(e) => write!(f, "failed to create VCPU: {}", e),
            CreateVm(e) => write!(f, "failed to create vm: {}", e),
            GetSerialCmdline(e) => write!(f, "failed to get serial cmdline: {}", e),
            InitrdLoadFailure(e) => write!(f, "initrd cound not be loaded: {}", e),
            KernelLoadFailure(e) => write!(f, "kernel cound not be loaded: {}", e),
            KernelMissing => write!(f, "aarch64 requires a kernel"),
            RegisterIrqfd(e) => write!(f, "failed to register irq fd: {}", e),
            RegisterPci(e) => write!(f, "error registering PCI bus: {}", e),
            RegisterVsock(e) => write!(f, "error registering virtual socket device: {}", e),
            SetDeviceAttr(e) => write!(f, "failed to set device attr: {}", e),
            SetReg(e) => write!(f, "failed to set register: {}", e),
            SetupGuestMemory(e) => write!(f, "failed to set up guest memory: {}", e),
            VcpuInit(e) => write!(f, "failed to initialize VCPU: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platfrom.
pub fn arch_memory_regions(size: u64) -> Vec<(GuestAddress, u64)> {
    vec![(GuestAddress(AARCH64_PHYS_MEM_START), size)]
}

fn fdt_offset(mem_size: u64) -> u64 {
    // Put fdt up near the top of memory
    // TODO(sonnyrao): will have to handle this differently if there's
    // > 4GB memory
    mem_size - AARCH64_FDT_MAX_SIZE - 0x10000
}

pub struct AArch64;

impl arch::LinuxArch for AArch64 {
    type Error = Error;

    fn build_vm<V, I, FD, FV, FI, E1, E2, E3>(
        mut components: VmComponents,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        create_devices: FD,
        create_vm: FV,
        create_irq_chip: FI,
    ) -> std::result::Result<RunnableLinuxVm<V, I>, Self::Error>
    where
        V: VmAArch64,
        I: IrqChipAArch64<V::Vcpu>,
        FD: FnOnce(
            &GuestMemory,
            &mut V,
            &mut SystemAllocator,
            &Event,
        ) -> std::result::Result<Vec<(Box<dyn PciDevice>, Option<Minijail>)>, E1>,
        FV: FnOnce(GuestMemory) -> std::result::Result<V, E2>,
        FI: FnOnce(&V, /* vcpu_count: */ usize) -> std::result::Result<I, E3>,
        E1: StdError + 'static,
        E2: StdError + 'static,
        E3: StdError + 'static,
    {
        let mut resources =
            Self::get_resource_allocator(components.memory_size, components.wayland_dmabuf);
        let mem = Self::setup_memory(components.memory_size)?;
        let mut vm = create_vm(mem.clone()).map_err(|e| Error::CreateVm(Box::new(e)))?;

        let mut use_pmu = vm
            .get_hypervisor()
            .check_capability(&HypervisorCap::ArmPmuV3);
        let vcpu_count = components.vcpu_count;
        let mut vcpus = Vec::with_capacity(vcpu_count);
        for vcpu_id in 0..vcpu_count {
            let vcpu = vm.create_vcpu(vcpu_id).map_err(Error::CreateVcpu)?;
            Self::configure_vcpu_early(vm.get_memory(), &vcpu, vcpu_id, use_pmu)?;
            vcpus.push(vcpu);
        }

        let mut irq_chip =
            create_irq_chip(&vm, vcpu_count).map_err(|e| Error::CreateIrqChip(Box::new(e)))?;

        for vcpu in &vcpus {
            use_pmu &= vcpu.init_pmu(AARCH64_PMU_IRQ as u64 + 16).is_ok();
        }

        let mut mmio_bus = devices::Bus::new();

        let exit_evt = Event::new().map_err(Error::CreateEvent)?;

        // Event used by PMDevice to notify crosvm that
        // guest OS is trying to suspend.
        let suspend_evt = Event::new().map_err(Error::CreateEvent)?;

        let pci_devices = create_devices(&mem, &mut vm, &mut resources, &exit_evt)
            .map_err(|e| Error::CreateDevices(Box::new(e)))?;
        let (pci, pci_irqs, pid_debug_label_map) = arch::generate_pci_root(
            pci_devices,
            &mut irq_chip,
            &mut mmio_bus,
            &mut resources,
            &mut vm,
            (devices::AARCH64_GIC_NR_IRQS - AARCH64_IRQ_BASE) as usize,
        )
        .map_err(Error::CreatePciRoot)?;
        let pci_bus = Arc::new(Mutex::new(PciConfigMmio::new(pci)));

        // ARM doesn't really use the io bus like x86, so just create an empty bus.
        let io_bus = devices::Bus::new();

        Self::add_arch_devs(&mut irq_chip, &mut mmio_bus)?;

        let com_evt_1_3 = Event::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = Event::new().map_err(Error::CreateEvent)?;
        arch::add_serial_devices(
            &mut mmio_bus,
            &com_evt_1_3,
            &com_evt_2_4,
            serial_parameters,
            serial_jail,
        )
        .map_err(Error::CreateSerialDevices)?;

        irq_chip
            .register_irq_event(AARCH64_SERIAL_1_3_IRQ, &com_evt_1_3, None)
            .map_err(Error::RegisterIrqfd)?;
        irq_chip
            .register_irq_event(AARCH64_SERIAL_2_4_IRQ, &com_evt_2_4, None)
            .map_err(Error::RegisterIrqfd)?;

        mmio_bus
            .insert(
                pci_bus.clone(),
                AARCH64_PCI_CFG_BASE,
                AARCH64_PCI_CFG_SIZE,
                false,
            )
            .map_err(Error::RegisterPci)?;

        let mut cmdline = Self::get_base_linux_cmdline();
        get_serial_cmdline(&mut cmdline, serial_parameters, "mmio")
            .map_err(Error::GetSerialCmdline)?;
        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        let kernel_image = if let VmImage::Kernel(ref mut img) = components.vm_image {
            img
        } else {
            return Err(Error::KernelMissing);
        };

        // separate out kernel loading from other setup to get a specific error for
        // kernel loading
        let kernel_size = arch::load_image(&mem, kernel_image, get_kernel_addr(), u64::max_value())
            .map_err(Error::KernelLoadFailure)?;
        let kernel_end = get_kernel_addr().offset() + kernel_size as u64;
        Self::setup_system_memory(
            &mem,
            components.memory_size,
            vcpu_count,
            &CString::new(cmdline).unwrap(),
            components.initrd_image,
            pci_irqs,
            components.android_fstab,
            kernel_end,
            irq_chip.get_vgic_version() == DeviceKind::ArmVgicV3,
            use_pmu,
        )?;

        Ok(RunnableLinuxVm {
            vm,
            resources,
            exit_evt,
            vcpu_count,
            vcpus: Some(vcpus),
            vcpu_affinity: components.vcpu_affinity,
            no_smt: components.no_smt,
            irq_chip,
            has_bios: false,
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            suspend_evt,
            rt_cpus: components.rt_cpus,
        })
    }

    fn configure_vcpu<T: VcpuAArch64>(
        _guest_mem: &GuestMemory,
        _hypervisor: &impl Hypervisor,
        _irq_chip: &mut impl IrqChipAArch64<T>,
        _vcpu: &mut impl VcpuAArch64,
        _vcpu_id: usize,
        _num_cpus: usize,
        _has_bios: bool,
        _no_smt: bool,
    ) -> std::result::Result<(), Self::Error> {
        // AArch64 doesn't configure vcpus on the vcpu thread, so nothing to do here.
        Ok(())
    }
}

impl AArch64 {
    fn setup_system_memory(
        mem: &GuestMemory,
        mem_size: u64,
        vcpu_count: usize,
        cmdline: &CStr,
        initrd_file: Option<File>,
        pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
        android_fstab: Option<File>,
        kernel_end: u64,
        is_gicv3: bool,
        use_pmu: bool,
    ) -> Result<()> {
        let initrd = match initrd_file {
            Some(initrd_file) => {
                let mut initrd_file = initrd_file;
                let initrd_addr =
                    (kernel_end + (AARCH64_INITRD_ALIGN - 1)) & !(AARCH64_INITRD_ALIGN - 1);
                let initrd_max_size = mem_size - (initrd_addr - AARCH64_PHYS_MEM_START);
                let initrd_addr = GuestAddress(initrd_addr);
                let initrd_size =
                    arch::load_image(mem, &mut initrd_file, initrd_addr, initrd_max_size)
                        .map_err(Error::InitrdLoadFailure)?;
                Some((initrd_addr, initrd_size))
            }
            None => None,
        };
        let (pci_device_base, pci_device_size) = Self::get_high_mmio_base_size(mem_size);
        fdt::create_fdt(
            AARCH64_FDT_MAX_SIZE as usize,
            mem,
            pci_irqs,
            vcpu_count as u32,
            fdt_offset(mem_size),
            pci_device_base,
            pci_device_size,
            cmdline,
            initrd,
            android_fstab,
            is_gicv3,
            use_pmu,
        )
        .map_err(Error::CreateFdt)?;
        Ok(())
    }

    fn setup_memory(mem_size: u64) -> Result<GuestMemory> {
        let arch_mem_regions = arch_memory_regions(mem_size);
        let mem = GuestMemory::new(&arch_mem_regions).map_err(Error::SetupGuestMemory)?;
        Ok(mem)
    }

    fn get_high_mmio_base_size(mem_size: u64) -> (u64, u64) {
        let base = AARCH64_PHYS_MEM_START + mem_size;
        let size = u64::max_value() - base;
        (base, size)
    }

    /// This returns a base part of the kernel command for this architecture
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(base::pagesize());
        cmdline.insert_str("panic=-1").unwrap();
        cmdline
    }

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem_size: u64, gpu_allocation: bool) -> SystemAllocator {
        let (high_mmio_base, high_mmio_size) = Self::get_high_mmio_base_size(mem_size);
        SystemAllocator::builder()
            .add_high_mmio_addresses(high_mmio_base, high_mmio_size)
            .add_low_mmio_addresses(AARCH64_MMIO_BASE, AARCH64_MMIO_SIZE)
            .create_allocator(AARCH64_IRQ_BASE, gpu_allocation)
            .unwrap()
    }

    /// This adds any early platform devices for this architecture.
    ///
    /// # Arguments
    ///
    /// * `irq_chip` - The IRQ chip to add irqs to.
    /// * `bus` - The bus to add devices to.
    fn add_arch_devs<T: VcpuAArch64>(irq_chip: &mut impl IrqChip<T>, bus: &mut Bus) -> Result<()> {
        let rtc_evt = Event::new().map_err(Error::CreateEvent)?;
        irq_chip
            .register_irq_event(AARCH64_RTC_IRQ, &rtc_evt, None)
            .map_err(Error::RegisterIrqfd)?;

        let rtc = Arc::new(Mutex::new(devices::pl030::Pl030::new(rtc_evt)));
        bus.insert(rtc, AARCH64_RTC_ADDR, AARCH64_RTC_SIZE, false)
            .expect("failed to add rtc device");

        Ok(())
    }

    /// Sets up `vcpu`.
    ///
    /// AArch64 needs vcpus set up before its kernel IRQ chip is created, so `configure_vcpu_early`
    /// is called from `build_vm` on the main thread.  `LinuxArch::configure_vcpu`, which is used
    /// by X86_64 to do setup later from the vcpu thread, is a no-op on AArch64 since vcpus were
    /// already configured here.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory object.
    /// * `vcpu` - The vcpu to configure.
    /// * `vcpu_id` - The VM's index for `vcpu`.
    /// * `use_pmu` - Should `vcpu` be configured to use the Performance Monitor Unit.
    fn configure_vcpu_early(
        guest_mem: &GuestMemory,
        vcpu: &impl VcpuAArch64,
        vcpu_id: usize,
        use_pmu: bool,
    ) -> Result<()> {
        let mut features = vec![VcpuFeature::PsciV0_2];
        if use_pmu {
            features.push(VcpuFeature::PmuV3);
        }
        // Non-boot cpus are powered off initially
        if vcpu_id != 0 {
            features.push(VcpuFeature::PowerOff)
        }
        vcpu.init(&features).map_err(Error::VcpuInit)?;

        // set up registers
        let mut data: u64;
        let mut reg_id: u64;

        // All interrupts masked
        data = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1H;
        reg_id = arm64_core_reg!(pstate);
        vcpu.set_one_reg(reg_id, data).map_err(Error::SetReg)?;

        // Other cpus are powered off initially
        if vcpu_id == 0 {
            data = AARCH64_PHYS_MEM_START + AARCH64_KERNEL_OFFSET;
            reg_id = arm64_core_reg!(pc);
            vcpu.set_one_reg(reg_id, data).map_err(Error::SetReg)?;

            /* X0 -- fdt address */
            let mem_size = guest_mem.memory_size();
            data = (AARCH64_PHYS_MEM_START + fdt_offset(mem_size)) as u64;
            // hack -- can't get this to do offsetof(regs[0]) but luckily it's at offset 0
            reg_id = arm64_core_reg!(regs);
            vcpu.set_one_reg(reg_id, data).map_err(Error::SetReg)?;
        }

        Ok(())
    }
}
