// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! RISC-V 64-bit architecture support.

#![cfg(target_arch = "riscv64")]

use std::collections::BTreeMap;
use std::io::{self};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use arch::get_serial_cmdline;
use arch::GetSerialCmdlineError;
use arch::RunnableLinuxVm;
use arch::VmComponents;
use arch::VmImage;
use base::Event;
use base::SendTube;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::Bus;
use devices::BusDeviceObj;
use devices::BusError;
use devices::IrqChipRiscv64;
use devices::PciAddress;
use devices::PciConfigMmio;
use devices::PciDevice;
use devices::PciRootCommand;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::riscv::Riscv64 as GdbArch;
use hypervisor::CoreRegister;
use hypervisor::CpuConfigRiscv64;
use hypervisor::Hypervisor;
use hypervisor::ProtectionType;
use hypervisor::TimerRegister;
use hypervisor::VcpuInitRiscv64;
use hypervisor::VcpuRegister;
use hypervisor::VcpuRiscv64;
use hypervisor::Vm;
use hypervisor::VmRiscv64;
#[cfg(windows)]
use jail::FakeMinijailStub as Minijail;
#[cfg(unix)]
use minijail::Minijail;
use remain::sorted;
use resources::AddressRange;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
#[cfg(unix)]
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_control::BatteryType;
use vm_memory::GuestAddress;
#[cfg(feature = "gdb")]
use vm_memory::GuestMemory;
use vm_memory::MemoryRegionOptions;

mod fdt;

// We place the kernel at offset 8MB
const RISCV64_KERNEL_OFFSET: u64 = 0x20_0000;
const RISCV64_INITRD_ALIGN: u64 = 8;
const RISCV64_FDT_ALIGN: u64 = 0x40_0000;

// This indicates the start of DRAM inside the physical address space.
const RISCV64_PHYS_MEM_START: u64 = 0x8000_0000;

// PCI MMIO configuration region base address.
const RISCV64_PCI_CFG_BASE: u64 = 0x1_0000;
// PCI MMIO configuration region size.
const RISCV64_PCI_CFG_SIZE: u64 = 0x100_0000;
// This is the base address of MMIO devices.
const RISCV64_MMIO_BASE: u64 = 0x0300_0000;
// Size of the whole MMIO region.
const RISCV64_MMIO_SIZE: u64 = 0x10_0000;

const RISCV64_FDT_MAX_SIZE: u64 = 0x1_0000;

fn get_kernel_addr() -> GuestAddress {
    GuestAddress(RISCV64_PHYS_MEM_START + RISCV64_KERNEL_OFFSET)
}

const RISCV64_IRQ_BASE: u32 = 1;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("unable to clone an Event: {0}")]
    CloneEvent(base::Error),
    #[error("failed to clone IRQ chip: {0}")]
    CloneIrqChip(base::Error),
    #[error("the given kernel command line was invalid: {0}")]
    Cmdline(kernel_cmdline::Error),
    #[error("unable to make an Event: {0}")]
    CreateEvent(base::Error),
    #[error("FDT could not be created: {0}")]
    CreateFdt(cros_fdt::Error),
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
    #[error("vm created wrong kind of vcpu")]
    DowncastVcpu,
    #[error("failed to finalize devices: {0}")]
    FinalizeDevices(base::Error),
    #[error("failed to finalize IRQ chip: {0}")]
    FinalizeIrqChip(base::Error),
    #[error("failed to get serial cmdline: {0}")]
    GetSerialCmdline(GetSerialCmdlineError),
    #[error("Failed to get the timer base frequency: {0}")]
    GetTimebase(base::Error),
    #[error("Image type not supported on riscv")]
    ImageTypeUnsupported,
    #[error("initrd could not be loaded: {0}")]
    InitrdLoadFailure(arch::LoadImageError),
    #[error("kernel could not be loaded: {0}")]
    KernelLoadFailure(arch::LoadImageError),
    #[error("protected vms not supported on riscv(yet)")]
    ProtectedVmUnsupported,
    #[error("ramoops address is different from high_mmio_base: {0} vs {1}")]
    RamoopsAddress(u64, u64),
    #[error("failed to register irq fd: {0}")]
    RegisterIrqfd(base::Error),
    #[error("error registering PCI bus: {0}")]
    RegisterPci(BusError),
    #[error("error registering virtual socket device: {0}")]
    RegisterVsock(arch::DeviceRegistrationError),
    #[error("failed to set device attr: {0}")]
    SetDeviceAttr(base::Error),
    #[error("failed to set register: {0}")]
    SetReg(base::Error),
    #[error("Timebase frequency too large")]
    TimebaseTooLarge,
    #[error("this function isn't supported")]
    Unsupported,
    #[error("failed to initialize VCPU: {0}")]
    VcpuInit(base::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Riscv64;

impl arch::LinuxArch for Riscv64 {
    type Error = Error;

    /// Returns a Vec of the valid memory addresses.
    /// These should be used to configure the GuestMemory structure for the platfrom.
    fn guest_memory_layout(
        components: &VmComponents,
        _hypervisor: &impl Hypervisor,
    ) -> std::result::Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>, Self::Error> {
        Ok(vec![(
            GuestAddress(RISCV64_PHYS_MEM_START),
            components.memory_size,
            Default::default(),
        )])
    }

    fn get_system_allocator_config<V: Vm>(vm: &V) -> SystemAllocatorConfig {
        get_resource_allocator_config(vm.get_memory().memory_size(), vm.get_guest_phys_addr_bits())
    }

    fn build_vm<V, Vcpu>(
        mut components: VmComponents,
        _vm_evt_wrtube: &SendTube,
        system_allocator: &mut SystemAllocator,
        serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        serial_jail: Option<Minijail>,
        (_bat_type, _bat_jail): (Option<BatteryType>, Option<Minijail>),
        mut vm: V,
        ramoops_region: Option<arch::pstore::RamoopsRegion>,
        devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
        irq_chip: &mut dyn IrqChipRiscv64,
        vcpu_ids: &mut Vec<usize>,
        _dump_device_tree_blob: Option<PathBuf>,
        _debugcon_jail: Option<Minijail>,
        #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
        #[cfg(unix)] _guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) -> std::result::Result<RunnableLinuxVm<V, Vcpu>, Self::Error>
    where
        V: VmRiscv64,
        Vcpu: VcpuRiscv64,
    {
        if components.hv_cfg.protection_type == ProtectionType::Protected {
            return Err(Error::ProtectedVmUnsupported);
        }

        let mem = vm.get_memory().clone();

        let mmio_bus = Arc::new(Bus::new());

        // Riscv doesn't really use the io bus like x86, so just create an empty bus.
        let io_bus = Arc::new(Bus::new());

        let com_evt_1_3 = Event::new().map_err(Error::CreateEvent)?;
        let com_evt_2_4 = Event::new().map_err(Error::CreateEvent)?;
        arch::add_serial_devices(
            components.hv_cfg.protection_type,
            &mmio_bus,
            &com_evt_1_3,
            &com_evt_2_4,
            serial_parameters,
            serial_jail,
            #[cfg(feature = "swap")]
            swap_controller,
        )
        .map_err(Error::CreateSerialDevices)?;

        let (pci_devices, others): (Vec<_>, Vec<_>) = devices
            .into_iter()
            .partition(|(dev, _)| dev.as_pci_device().is_some());
        let pci_devices = pci_devices
            .into_iter()
            .map(|(dev, jail_orig)| (dev.into_pci_device().unwrap(), jail_orig))
            .collect();
        let (pci, pci_irqs, mut pid_debug_label_map, _amls) = arch::generate_pci_root(
            pci_devices,
            irq_chip.as_irq_chip_mut(),
            Arc::clone(&mmio_bus),
            Arc::clone(&io_bus),
            system_allocator,
            &mut vm,
            devices::IMSIC_MAX_INT_IDS as usize,
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
        let (platform_devices, mut platform_pid_debug_label_map) =
            arch::sys::unix::generate_platform_bus(
                platform_devices,
                irq_chip.as_irq_chip_mut(),
                &mmio_bus,
                system_allocator,
                #[cfg(feature = "swap")]
                swap_controller,
            )
            .map_err(Error::CreatePlatformBus)?;
        pid_debug_label_map.append(&mut platform_pid_debug_label_map);

        let mut cmdline = get_base_linux_cmdline();

        if let Some(ramoops_region) = ramoops_region {
            arch::pstore::add_ramoops_kernel_cmdline(&mut cmdline, &ramoops_region)
                .map_err(Error::Cmdline)?;
        }

        mmio_bus
            .insert(pci_bus, RISCV64_PCI_CFG_BASE, RISCV64_PCI_CFG_SIZE)
            .map_err(Error::RegisterPci)?;

        get_serial_cmdline(&mut cmdline, serial_parameters, "mmio")
            .map_err(Error::GetSerialCmdline)?;
        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        // Event used by PMDevice to notify crosvm that guest OS is trying to suspend.
        let suspend_evt = Event::new().map_err(Error::CreateEvent)?;

        // separate out image loading from other setup to get a specific error for
        // image loading
        let initrd;
        let kernel_initrd_end = match components.vm_image {
            VmImage::Bios(ref _bios) => {
                return Err(Error::ImageTypeUnsupported);
            }
            VmImage::Kernel(ref mut kernel_image) => {
                let kernel_size =
                    arch::load_image(&mem, kernel_image, get_kernel_addr(), u64::max_value())
                        .map_err(Error::KernelLoadFailure)?;
                let kernel_end = get_kernel_addr().offset() + kernel_size as u64;
                initrd = match components.initrd_image {
                    Some(initrd_file) => {
                        let mut initrd_file = initrd_file;
                        let initrd_addr =
                            (kernel_end + (RISCV64_INITRD_ALIGN - 1)) & !(RISCV64_INITRD_ALIGN - 1);
                        let initrd_max_size =
                            components.memory_size - (initrd_addr - RISCV64_PHYS_MEM_START);
                        let initrd_addr = GuestAddress(initrd_addr);
                        let initrd_size =
                            arch::load_image(&mem, &mut initrd_file, initrd_addr, initrd_max_size)
                                .map_err(Error::InitrdLoadFailure)?;
                        Some((initrd_addr, initrd_size))
                    }
                    None => None,
                };
                if let Some((initrd_addr, initrd_size)) = initrd {
                    initrd_addr.offset() + initrd_size as u64 - RISCV64_PHYS_MEM_START
                } else {
                    kernel_end - RISCV64_PHYS_MEM_START
                }
            }
        };

        // Creates vcpus early as the irqchip needs them created to attach interrupts.
        let vcpu_count = components.vcpu_count;
        let mut vcpus = Vec::with_capacity(vcpu_count);
        for vcpu_id in 0..vcpu_count {
            let vcpu: Vcpu = *vm
                .create_vcpu(vcpu_id)
                .map_err(Error::CreateVcpu)?
                .downcast::<Vcpu>()
                .map_err(|_| Error::DowncastVcpu)?;
            vcpus.push(vcpu);
            vcpu_ids.push(vcpu_id);
        }

        irq_chip.finalize().map_err(Error::FinalizeIrqChip)?;

        irq_chip
            .finalize_devices(system_allocator, &io_bus, &mmio_bus)
            .map_err(Error::FinalizeDevices)?;
        let (aia_num_ids, aia_num_sources) = irq_chip.get_num_ids_sources();

        let pci_cfg = fdt::PciConfigRegion {
            base: RISCV64_PCI_CFG_BASE,
            size: RISCV64_PCI_CFG_SIZE,
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

        let fdt_offset = (kernel_initrd_end + (RISCV64_FDT_ALIGN - 1)) & !(RISCV64_FDT_ALIGN - 1);

        let timebase_freq: u32 = vcpus[0]
            .get_one_reg(VcpuRegister::Timer(TimerRegister::TimebaseFrequency))
            .map_err(Error::GetTimebase)?
            .try_into()
            .map_err(|_| Error::TimebaseTooLarge)?;

        fdt::create_fdt(
            RISCV64_FDT_MAX_SIZE as usize,
            &mem,
            pci_irqs,
            pci_cfg,
            &pci_ranges,
            components.vcpu_count as u32,
            fdt_offset,
            aia_num_ids,
            aia_num_sources,
            cmdline.as_str(),
            initrd,
            timebase_freq,
        )
        .map_err(Error::CreateFdt)?;

        let vcpu_init = vec![
            VcpuInitRiscv64::new(GuestAddress(fdt_offset + RISCV64_PHYS_MEM_START));
            vcpu_count
        ];

        Ok(RunnableLinuxVm {
            vm,
            vcpu_count: components.vcpu_count,
            vcpus: Some(vcpus),
            vcpu_init,
            vcpu_affinity: components.vcpu_affinity,
            no_smt: false,
            irq_chip: irq_chip.try_box_clone().map_err(Error::CloneIrqChip)?,
            has_bios: false,
            io_bus,
            mmio_bus,
            pid_debug_label_map,
            resume_notify_devices: Vec::new(),
            root_config: pci_root,
            platform_devices,
            hotplug_bus: BTreeMap::new(),
            rt_cpus: components.rt_cpus,
            delay_rt: components.delay_rt,
            suspend_evt,
            bat_control: None,
            #[cfg(feature = "gdb")]
            gdb: components.gdb,
            pm: None,
            devices_thread: None,
            vm_request_tube: None,
        })
    }

    fn configure_vcpu<V: Vm>(
        _vm: &V,
        _hypervisor: &dyn Hypervisor,
        _irq_chip: &mut dyn IrqChipRiscv64,
        vcpu: &mut dyn VcpuRiscv64,
        _vcpu_init: VcpuInitRiscv64,
        vcpu_id: usize,
        _num_cpus: usize,
        _has_bios: bool,
        cpu_config: Option<CpuConfigRiscv64>,
    ) -> std::result::Result<(), Self::Error> {
        vcpu.set_one_reg(VcpuRegister::Core(CoreRegister::Pc), get_kernel_addr().0)
            .map_err(Self::Error::SetReg)?;
        vcpu.set_one_reg(VcpuRegister::Core(CoreRegister::A0), vcpu_id as u64)
            .map_err(Self::Error::SetReg)?;
        vcpu.set_one_reg(
            VcpuRegister::Core(CoreRegister::A1),
            cpu_config.unwrap().fdt_address.0,
        )
        .map_err(Self::Error::SetReg)?;

        Ok(())
    }

    fn register_pci_device<V: VmRiscv64, Vcpu: VcpuRiscv64>(
        _linux: &mut RunnableLinuxVm<V, Vcpu>,
        _device: Box<dyn PciDevice>,
        _minijail: Option<Minijail>,
        _resources: &mut SystemAllocator,
        _tube: &mpsc::Sender<PciRootCommand>,
        #[cfg(feature = "swap")] _swap_controller: &mut Option<swap::SwapController>,
    ) -> std::result::Result<PciAddress, Self::Error> {
        // hotplug function isn't verified on Riscv64, so set it unsupported here.
        Err(Error::Unsupported)
    }

    fn get_host_cpu_frequencies_khz() -> Result<BTreeMap<usize, Vec<u32>>> {
        Ok(BTreeMap::new())
    }
}

#[cfg(feature = "gdb")]
impl<T: VcpuRiscv64> arch::GdbOps<T> for Riscv64 {
    type Error = Error;

    fn read_memory(
        _vcpu: &T,
        _guest_mem: &GuestMemory,
        _vaddr: GuestAddress,
        _len: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }

    fn write_memory(
        _vcpu: &T,
        _guest_mem: &GuestMemory,
        _vaddr: GuestAddress,
        _buf: &[u8],
    ) -> Result<()> {
        unimplemented!();
    }

    fn read_registers(_vcpu: &T) -> Result<<GdbArch as Arch>::Registers> {
        unimplemented!();
    }

    fn write_registers(_vcpu: &T, _regs: &<GdbArch as Arch>::Registers) -> Result<()> {
        unimplemented!();
    }

    fn read_register(_vcpu: &T, _reg_id: <GdbArch as Arch>::RegId) -> Result<Vec<u8>> {
        unimplemented!();
    }

    fn write_register(_vcpu: &T, _reg_id: <GdbArch as Arch>::RegId, _data: &[u8]) -> Result<()> {
        unimplemented!();
    }

    fn enable_singlestep(_vcpu: &T) -> Result<()> {
        unimplemented!();
    }

    fn get_max_hw_breakpoints(_vcpu: &T) -> Result<usize> {
        unimplemented!();
    }

    fn set_hw_breakpoints(_vcpu: &T, _breakpoints: &[GuestAddress]) -> Result<()> {
        unimplemented!();
    }
}

fn get_high_mmio_base_size(mem_size: u64, guest_phys_addr_bits: u8) -> (u64, u64) {
    let guest_phys_end = 1u64 << guest_phys_addr_bits;
    let high_mmio_base = RISCV64_PHYS_MEM_START + mem_size;
    let size = guest_phys_end
        .checked_sub(high_mmio_base)
        .unwrap_or_else(|| {
            panic!(
                "guest_phys_end {:#x} < high_mmio_base {:#x}",
                guest_phys_end, high_mmio_base,
            );
        });
    (high_mmio_base, size)
}

fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
    let mut cmdline = kernel_cmdline::Cmdline::new(base::pagesize());
    cmdline.insert_str("panic=-1").unwrap();
    cmdline
}

/// Returns a system resource allocator coniguration.
///
/// # Arguments
///
/// * `mem_size` - Size of guest memory (RAM) in bytes.
/// * `guest_phys_addr_bits` - Size of guest physical addresses (IPA) in bits.
fn get_resource_allocator_config(mem_size: u64, guest_phys_addr_bits: u8) -> SystemAllocatorConfig {
    let (high_mmio_base, high_mmio_size) = get_high_mmio_base_size(mem_size, guest_phys_addr_bits);
    SystemAllocatorConfig {
        io: None,
        low_mmio: AddressRange::from_start_and_size(RISCV64_MMIO_BASE, RISCV64_MMIO_SIZE)
            .expect("invalid mmio region"),
        high_mmio: AddressRange::from_start_and_size(high_mmio_base, high_mmio_size)
            .expect("invalid high mmio region"),
        platform_mmio: None,
        first_irq: RISCV64_IRQ_BASE,
    }
}
