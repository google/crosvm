// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate arch;
extern crate byteorder;
extern crate data_model;
extern crate devices;
extern crate kernel_cmdline;
extern crate kvm;
extern crate kvm_sys;
extern crate libc;
extern crate sys_util;
extern crate resources;

use std::error::{self, Error as Aarch64Error};
use std::fmt::{self, Display};
use std::fs::File;
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::ffi::CStr;

use devices::Bus;
use sys_util::{EventFd, GuestAddress, GuestMemory};
use resources::{AddressRanges, SystemAllocator};
use std::os::unix::io::FromRawFd;

use kvm::*;
use kvm_sys::kvm_device_attr;

use arch::Result;
mod fdt;

// We place the kernel at offset 8MB
const AARCH64_KERNEL_OFFSET: u64 = 0x80000;
const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64  = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64  = 0x20000;

// This indicates the start of DRAM inside the physical address space.
const AARCH64_PHYS_MEM_START: u64 = 0x80000000;
const AARCH64_AXI_BASE: u64       = 0x40000000;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64  = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_CPUI_BASE: u64  = AARCH64_GIC_DIST_BASE -
    AARCH64_GIC_CPUI_SIZE;

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

const KVM_REG_ARM64: u64    = 0x6000000000000000;
const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
const KVM_REG_ARM_COPROC_SHIFT: u64 = 16;
const KVM_REG_ARM_CORE: u64 = 0x0010 << KVM_REG_ARM_COPROC_SHIFT;

macro_rules! arm64_core_reg {
    ($reg: tt) => {
        KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | ((offset__of!(kvm_sys::user_pt_regs, $reg) / 4) as u64)
    };
}

fn get_kernel_addr() -> GuestAddress {
    GuestAddress(AARCH64_PHYS_MEM_START + AARCH64_KERNEL_OFFSET)
}

// Place the serial device at a typical address for x86.
const AARCH64_SERIAL_ADDR: u64 = 0x3F8;
// Serial device requires 8 bytes of registers;
const AARCH64_SERIAL_SIZE: u64 = 0x8;
// This was the speed kvmtool used, not sure if it matters.
const AARCH64_SERIAL_SPEED: u32 = 1843200;

// Place the RTC device at page 2
const AARCH64_RTC_ADDR: u64 = 0x2000;
// The RTC device gets one 4k page
const AARCH64_RTC_SIZE: u64 = 0x1000;
// The RTC device gets the first interrupt line
// Which gets mapped to the first SPI interrupt (physical 32).
const AARCH64_RTC_IRQ: u32  = 0;

// This is the base address of MMIO devices.
const AARCH64_MMIO_BASE: u64 = 0x10000;
// Each MMIO device gets a 4k page.
const AARCH64_MMIO_LEN: u64 = 0x1000;
// Virtio devices start at SPI interrupt number 1
const AARCH64_IRQ_BASE: u32 = 1;

#[derive(Debug)]
pub enum Error {
    /// FDT could not be created
    FDTCreateFailure(Box<error::Error>),
    /// Kernel could not be loaded
    KernelLoadFailure,
    /// Failure to Create GIC
    CreateGICFailure(sys_util::Error),
    /// VCPU Init failed
    VCPUInitFailure,
    /// VCPU Set one reg failed
    VCPUSetRegFailure,
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::FDTCreateFailure(_) =>
                "FDT could not be created",
            &Error::KernelLoadFailure =>
                "Kernel cound not be loaded",
            &Error::CreateGICFailure(_) =>
                "Failure to create GIC",
            &Error::VCPUInitFailure =>
                "Failed to initialize VCPU",
            &Error::VCPUSetRegFailure =>
                "Failed to set register",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Aarch64 Error: {}", Error::description(self))
    }
}

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
    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    fn load_kernel(guest_mem: &GuestMemory, mut kernel_image: &mut File) -> Result<()> {
        let kernel_addr = get_kernel_addr();
        let kernel_meta = kernel_image.metadata()?;
        let kernel_size = kernel_meta.len();
        guest_mem.read_to_memory(kernel_addr, &mut kernel_image, kernel_size as usize).
            map_err(|_| Error::KernelLoadFailure)?;
        Ok(())
    }

    fn setup_system_memory(mem: &GuestMemory, mem_size: u64, vcpu_count: u32,
                           cmdline: &CStr) -> Result<()> {
        fdt::create_fdt(AARCH64_FDT_MAX_SIZE as usize,
                        mem,
                        vcpu_count,
                        fdt_offset(mem_size),
                        cmdline)?;
        Ok(())
    }

    fn create_vm(kvm: &Kvm, mem: GuestMemory) -> Result<Vm> {
        let vm = Vm::new(&kvm, mem)?;
        Ok(vm)
    }

    fn setup_memory(mem_size: u64) -> Result<GuestMemory> {
        let arch_mem_regions = arch_memory_regions(mem_size);
        let mem = GuestMemory::new(&arch_mem_regions)?;
        Ok(mem)
    }

    fn get_base_dev_pfn(mem_size: u64) -> u64 {
        (AARCH64_PHYS_MEM_START + mem_size) >> 12
    }

    /// This returns a base part of the kernel command for this architecture
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(sys_util::pagesize());
        cmdline.insert_str("console=ttyS0 reboot=k panic=1").
            unwrap();
        cmdline
    }

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem_size: u64, gpu_allocation: bool) -> SystemAllocator {
        let device_addr_start = Self::get_base_dev_pfn(mem_size) * sys_util::pagesize() as u64;
        AddressRanges::new()
            .add_device_addresses(device_addr_start, u64::max_value() - device_addr_start)
            .add_mmio_addresses(AARCH64_MMIO_BASE, 0x10000)
            .create_allocator(AARCH64_IRQ_BASE, gpu_allocation).unwrap()
    }

    /// This adds any early platform devices for this architecture.
    ///
    /// # Arguments
    ///
    /// * `vm` - The vm to add irqs to.
    /// * `bus` - The bus to add devices to.
    fn add_arch_devs(vm: &mut Vm, bus: &mut Bus) -> Result<()> {
        let rtc_evt = EventFd::new()?;
        vm.register_irqfd(&rtc_evt, AARCH64_RTC_IRQ)?;

        let com_evt_1_3 = EventFd::new()?;
        let serial = Arc::new(Mutex::new(devices::Serial::new_out(
            com_evt_1_3.try_clone()?,
            Box::new(stdout()))));
        bus.insert(serial.clone(), AARCH64_SERIAL_ADDR, AARCH64_SERIAL_SIZE)
            .expect("failed to add serial device");

        let rtc = Arc::new(Mutex::new(devices::pl030::Pl030::new(rtc_evt)));
        bus.insert(rtc, AARCH64_RTC_ADDR, AARCH64_RTC_SIZE)
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
        vm.create_device(&mut kcd).map_err(|e| Error::CreateGICFailure(e))?;

        // Safe because the kernel is passing us an FD back inside
        // the struct after we successfully did the create_device ioctl
        let vgic_fd = unsafe { File::from_raw_fd(kcd.fd as i32) };

        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(),
                                     &cpu_if_attr)
        };
        if ret != 0 {
            return Err(Box::new(Error::CreateGICFailure(
                sys_util::Error::new(ret))))
        }

        // Safe because we allocated the struct that's being passed in
        let ret = unsafe {
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(),
                                     &dist_attr)
        };
        if ret != 0 {
            return Err(Box::new(Error::CreateGICFailure(
                sys_util::Error::new(ret))))
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
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(),
                                     &nr_irqs_attr)
        };
        if ret != 0 {
            return Err(Box::new(Error::CreateGICFailure(
                sys_util::Error::new(ret))))
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
            sys_util::ioctl_with_ref(&vgic_fd, kvm_sys::KVM_SET_DEVICE_ATTR(),
                                     &init_gic_attr)
        };
        if ret != 0 {
            return Err(Box::new(sys_util::Error::new(ret)))
        }
        Ok(Some(vgic_fd))
    }

    fn setup_io_bus(_vm: &mut Vm, _exit_evt: EventFd)
                    -> Result<(devices::Bus, Arc<Mutex<devices::Serial>>)> {
        // ARM doesn't really use the io bus like x86, instead we have a
        // separate serial device that is returned as a separate object.
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = EventFd::new()?;

        let serial = Arc::new(Mutex::new(devices::Serial::new_out(
            com_evt_1_3.try_clone()?,
            Box::new(stdout()))));
        Ok((io_bus, serial))
    }

    fn configure_vcpu(guest_mem: &GuestMemory,
                      _kvm: &Kvm,
                      vm: &Vm,
                      vcpu: &Vcpu,
                      cpu_id: u64,
                      _num_cpus: u64)
                      -> Result<()> {
        let mut kvi = kvm_sys::kvm_vcpu_init {
            target: kvm_sys::KVM_ARM_TARGET_GENERIC_V8,
            features: [0; 7],
        };

        // This reads back the kernel's preferred target type.
        vm.arm_preferred_target(&mut kvi)?;

        // TODO(sonnyrao): need to verify this feature is supported by host kernel
        kvi.features[0] |= 1 << kvm_sys::KVM_ARM_VCPU_PSCI_0_2;

        // Non-boot cpus are powered off initially
        if cpu_id > 0 {
            kvi.features[0] |= 1 << kvm_sys::KVM_ARM_VCPU_POWER_OFF;
        }
        vcpu.arm_vcpu_init(&kvi)?;

        // set up registers
        let mut data: u64;
        let mut reg_id: u64;

        // All interrupts masked
        data    = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1H;
        reg_id  = arm64_core_reg!(pstate);
        vcpu.set_one_reg(reg_id, data)?;

        // Other cpus are powered off initially
        if cpu_id == 0 {
            data    = AARCH64_PHYS_MEM_START + AARCH64_KERNEL_OFFSET;
            reg_id  = arm64_core_reg!(pc);
            vcpu.set_one_reg(reg_id, data)?;

            /* X0 -- fdt address */
            let mem_size = guest_mem.memory_size();
            data    = (AARCH64_PHYS_MEM_START + fdt_offset(mem_size)) as u64;
            // hack -- can't get this to do offsetof(regs[0]) but luckily it's at offset 0
            reg_id  = arm64_core_reg!(regs);
            vcpu.set_one_reg(reg_id, data)?;
        }
        Ok(())
    }

}
