// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use arch::{RunnableLinuxVm, VmComponents, VmImage};
use devices::{
    get_serial_tty_string, Bus, BusError, PciConfigMmio, PciDevice, PciInterruptPin,
    SerialParameters,
};
use io_jail::Minijail;
use remain::sorted;
use resources::SystemAllocator;
use sync::Mutex;
use sys_util::{EventFd, GuestAddress, GuestMemory, GuestMemoryError};

use kvm::*;
use kvm_sys::kvm_device_attr;

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

// This is the minimum number of SPI interrupts aligned to 32 + 32 for the
// PPI (16) and GSI (16).
const AARCH64_GIC_NR_IRQS: u32 = 64;

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

#[sorted]
#[derive(Debug)]
pub enum Error {
    CloneEventFd(sys_util::Error),
    Cmdline(kernel_cmdline::Error),
    CreateDevices(Box<dyn StdError>),
    CreateEventFd(sys_util::Error),
    CreateFdt(arch::fdt::Error),
    CreateGICFailure(sys_util::Error),
    CreateKvm(sys_util::Error),
    CreatePciRoot(arch::DeviceRegistrationError),
    CreateSerialDevices(arch::DeviceRegistrationError),
    CreateSocket(io::Error),
    CreateVcpu(sys_util::Error),
    CreateVm(sys_util::Error),
    InitrdLoadFailure(arch::LoadImageError),
    KernelLoadFailure(arch::LoadImageError),
    KernelMissing,
    ReadPreferredTarget(sys_util::Error),
    RegisterIrqfd(sys_util::Error),
    RegisterPci(BusError),
    RegisterVsock(arch::DeviceRegistrationError),
    SetDeviceAttr(sys_util::Error),
    SetReg(sys_util::Error),
    SetupGuestMemory(GuestMemoryError),
    VcpuInit(sys_util::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CloneEventFd(e) => write!(f, "unable to clone an EventFd: {}", e),
            Cmdline(e) => write!(f, "the given kernel command line was invalid: {}", e),
            CreateDevices(e) => write!(f, "error creating devices: {}", e),
            CreateEventFd(e) => write!(f, "unable to make an EventFd: {}", e),
            CreateFdt(e) => write!(f, "FDT could not be created: {}", e),
            CreateGICFailure(e) => write!(f, "failed to create GIC: {}", e),
            CreateKvm(e) => write!(f, "failed to open /dev/kvm: {}", e),
            CreatePciRoot(e) => write!(f, "failed to create a PCI root hub: {}", e),
            CreateSerialDevices(e) => write!(f, "unable to create serial devices: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateVcpu(e) => write!(f, "failed to create VCPU: {}", e),
            CreateVm(e) => write!(f, "failed to create vm: {}", e),
            InitrdLoadFailure(e) => write!(f, "initrd cound not be loaded: {}", e),
            KernelLoadFailure(e) => write!(f, "kernel cound not be loaded: {}", e),
            KernelMissing => write!(f, "aarch64 requires a kernel"),
            ReadPreferredTarget(e) => write!(f, "failed to read preferred target: {}", e),
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

    fn build_vm<F, E>(
        mut components: VmComponents,
        _split_irqchip: bool,
        serial_parameters: &BTreeMap<u8, SerialParameters>,
        create_devices: F,
    ) -> Result<RunnableLinuxVm>
    where
        F: FnOnce(
            &GuestMemory,
            &mut Vm,
            &mut SystemAllocator,
            &EventFd,
        ) -> std::result::Result<Vec<(Box<dyn PciDevice>, Option<Minijail>)>, E>,
        E: StdError + 'static,
    {
        let mut resources =
            Self::get_resource_allocator(components.memory_size, components.wayland_dmabuf);
        let mem = Self::setup_memory(components.memory_size)?;
        let kvm = Kvm::new().map_err(Error::CreateKvm)?;
        let mut vm = Vm::new(&kvm, mem.clone()).map_err(Error::CreateVm)?;

        let vcpu_count = components.vcpu_count;
        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        for cpu_id in 0..vcpu_count {
            let vcpu = Vcpu::new(cpu_id as libc::c_ulong, &kvm, &vm).map_err(Error::CreateVcpu)?;
            Self::configure_vcpu(
                vm.get_memory(),
                &kvm,
                &vm,
                &vcpu,
                cpu_id as u64,
                vcpu_count as u64,
            )?;
            vcpus.push(vcpu);
        }

        let vcpu_affinity = components.vcpu_affinity;

        let irq_chip = Self::create_irq_chip(&vm)?;

        let mut mmio_bus = devices::Bus::new();

        let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;

        let pci_devices = create_devices(&mem, &mut vm, &mut resources, &exit_evt)
            .map_err(|e| Error::CreateDevices(Box::new(e)))?;
        let (pci, pci_irqs, pid_debug_label_map) =
            arch::generate_pci_root(pci_devices, &mut mmio_bus, &mut resources, &mut vm)
                .map_err(Error::CreatePciRoot)?;
        let pci_bus = Arc::new(Mutex::new(PciConfigMmio::new(pci)));

        // ARM doesn't really use the io bus like x86, so just create an empty bus.
        let io_bus = devices::Bus::new();

        Self::add_arch_devs(&mut vm, &mut mmio_bus)?;

        let com_evt_1_3 = EventFd::new().map_err(Error::CreateEventFd)?;
        let com_evt_2_4 = EventFd::new().map_err(Error::CreateEventFd)?;
        let (stdio_serial_num, stdio_serial) = arch::add_serial_devices(
            &mut mmio_bus,
            &com_evt_1_3,
            &com_evt_2_4,
            &serial_parameters,
        )
        .map_err(Error::CreateSerialDevices)?;

        vm.register_irqfd(&com_evt_1_3, AARCH64_SERIAL_1_3_IRQ)
            .map_err(Error::RegisterIrqfd)?;
        vm.register_irqfd(&com_evt_2_4, AARCH64_SERIAL_2_4_IRQ)
            .map_err(Error::RegisterIrqfd)?;

        mmio_bus
            .insert(
                pci_bus.clone(),
                AARCH64_PCI_CFG_BASE,
                AARCH64_PCI_CFG_SIZE,
                false,
            )
            .map_err(Error::RegisterPci)?;

        let mut cmdline = Self::get_base_linux_cmdline(stdio_serial_num);
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
        )?;

        Ok(RunnableLinuxVm {
            vm,
            kvm,
            resources,
            stdio_serial,
            exit_evt,
            vcpus,
            vcpu_affinity,
            irq_chip,
            io_bus,
            mmio_bus,
            pid_debug_label_map,
        })
    }
}

impl AArch64 {
    fn setup_system_memory(
        mem: &GuestMemory,
        mem_size: u64,
        vcpu_count: u32,
        cmdline: &CStr,
        initrd_file: Option<File>,
        pci_irqs: Vec<(u32, PciInterruptPin)>,
        android_fstab: Option<File>,
        kernel_end: u64,
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
        let (pci_device_base, pci_device_size) = Self::get_device_addr_base_size(mem_size);
        fdt::create_fdt(
            AARCH64_FDT_MAX_SIZE as usize,
            mem,
            pci_irqs,
            vcpu_count,
            fdt_offset(mem_size),
            pci_device_base,
            pci_device_size,
            cmdline,
            initrd,
            android_fstab,
        )
        .map_err(Error::CreateFdt)?;
        Ok(())
    }

    fn setup_memory(mem_size: u64) -> Result<GuestMemory> {
        let arch_mem_regions = arch_memory_regions(mem_size);
        let mem = GuestMemory::new(&arch_mem_regions).map_err(Error::SetupGuestMemory)?;
        Ok(mem)
    }

    fn get_device_addr_base_size(mem_size: u64) -> (u64, u64) {
        let base = AARCH64_PHYS_MEM_START + mem_size;
        let size = u64::max_value() - base;
        (base, size)
    }

    /// This returns a base part of the kernel command for this architecture
    fn get_base_linux_cmdline(stdio_serial_num: Option<u8>) -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(sys_util::pagesize());
        if stdio_serial_num.is_some() {
            let tty_string = get_serial_tty_string(stdio_serial_num.unwrap());
            cmdline.insert("console", &tty_string).unwrap();
        }
        cmdline.insert_str("panic=-1").unwrap();
        cmdline
    }

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem_size: u64, gpu_allocation: bool) -> SystemAllocator {
        let (device_addr_base, device_addr_size) = Self::get_device_addr_base_size(mem_size);
        SystemAllocator::builder()
            .add_device_addresses(device_addr_base, device_addr_size)
            .add_mmio_addresses(AARCH64_MMIO_BASE, AARCH64_MMIO_SIZE)
            .create_allocator(AARCH64_IRQ_BASE, gpu_allocation)
            .unwrap()
    }

    /// This adds any early platform devices for this architecture.
    ///
    /// # Arguments
    ///
    /// * `vm` - The vm to add irqs to.
    /// * `bus` - The bus to add devices to.
    fn add_arch_devs(vm: &mut Vm, bus: &mut Bus) -> Result<()> {
        let rtc_evt = EventFd::new().map_err(Error::CreateEventFd)?;
        vm.register_irqfd(&rtc_evt, AARCH64_RTC_IRQ)
            .map_err(Error::RegisterIrqfd)?;

        let rtc = Arc::new(Mutex::new(devices::pl030::Pl030::new(rtc_evt)));
        bus.insert(rtc, AARCH64_RTC_ADDR, AARCH64_RTC_SIZE, false)
            .expect("failed to add rtc device");

        Ok(())
    }

    /// The creates the interrupt controller device and optionally returns the fd for it.
    /// Some architectures may not have a separate descriptor for the interrupt
    /// controller, so they would return None even on success.
    ///
    /// # Arguments
    ///
    /// * `vm` - the vm object
    fn create_irq_chip(vm: &Vm) -> Result<Option<File>> {
        let cpu_if_addr: u64 = AARCH64_GIC_CPUI_BASE;
        let dist_if_addr: u64 = AARCH64_GIC_DIST_BASE;
        let raw_cpu_if_addr = &cpu_if_addr as *const u64;
        let raw_dist_if_addr = &dist_if_addr as *const u64;

        let cpu_if_attr = kvm_device_attr {
            group: kvm_sys::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: kvm_sys::KVM_VGIC_V2_ADDR_TYPE_CPU as u64,
            addr: raw_cpu_if_addr as u64,
            flags: 0,
        };
        let dist_attr = kvm_device_attr {
            group: kvm_sys::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: kvm_sys::KVM_VGIC_V2_ADDR_TYPE_DIST as u64,
            addr: raw_dist_if_addr as u64,
            flags: 0,
        };
        let mut kcd = kvm_sys::kvm_create_device {
            type_: kvm_sys::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };
        vm.create_device(&mut kcd)
            .map_err(|e| Error::CreateGICFailure(e))?;

        // Safe because the kernel is passing us an FD back inside
        // the struct after we successfully did the create_device ioctl
        let vgic_fd = unsafe { File::from_raw_fd(kcd.fd as i32) };

        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(), &cpu_if_attr)
        };
        if ret != 0 {
            return Err(Error::CreateGICFailure(sys_util::Error::new(ret)));
        }

        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(), &dist_attr)
        };
        if ret != 0 {
            return Err(Error::CreateGICFailure(sys_util::Error::new(ret)));
        }

        // We need to tell the kernel how many irqs to support with this vgic
        let nr_irqs: u32 = AARCH64_GIC_NR_IRQS;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let nr_irqs_attr = kvm_device_attr {
            group: kvm_sys::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(), &nr_irqs_attr)
        };
        if ret != 0 {
            return Err(Error::CreateGICFailure(sys_util::Error::new(ret)));
        }

        // Finalize the GIC
        let init_gic_attr = kvm_device_attr {
            group: kvm_sys::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: kvm_sys::KVM_DEV_ARM_VGIC_CTRL_INIT as u64,
            addr: 0,
            flags: 0,
        };

        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(), &init_gic_attr)
        };
        if ret != 0 {
            return Err(Error::SetDeviceAttr(sys_util::Error::new(ret)));
        }
        Ok(Some(vgic_fd))
    }

    fn configure_vcpu(
        guest_mem: &GuestMemory,
        _kvm: &Kvm,
        vm: &Vm,
        vcpu: &Vcpu,
        cpu_id: u64,
        _num_cpus: u64,
    ) -> Result<()> {
        let mut kvi = kvm_sys::kvm_vcpu_init {
            target: kvm_sys::KVM_ARM_TARGET_GENERIC_V8,
            features: [0; 7],
        };

        // This reads back the kernel's preferred target type.
        vm.arm_preferred_target(&mut kvi)
            .map_err(Error::ReadPreferredTarget)?;

        // TODO(sonnyrao): need to verify this feature is supported by host kernel
        kvi.features[0] |= 1 << kvm_sys::KVM_ARM_VCPU_PSCI_0_2;

        // Non-boot cpus are powered off initially
        if cpu_id > 0 {
            kvi.features[0] |= 1 << kvm_sys::KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.arm_vcpu_init(&kvi).map_err(Error::VcpuInit)?;

        // set up registers
        let mut data: u64;
        let mut reg_id: u64;

        // All interrupts masked
        data = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1H;
        reg_id = arm64_core_reg!(pstate);
        vcpu.set_one_reg(reg_id, data).map_err(Error::SetReg)?;

        // Other cpus are powered off initially
        if cpu_id == 0 {
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
