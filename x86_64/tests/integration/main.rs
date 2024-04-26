// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// These tests are only implemented for kvm & gvm. Other hypervisors may be added in the future.
#![cfg(all(any(feature = "gvm", unix), target_arch = "x86_64"))]

mod sys;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;
use std::thread;

use arch::LinuxArch;
use arch::SmbiosOptions;
use base::Tube;
use devices::Bus;
use devices::BusType;
use devices::IrqChipX86_64;
use devices::PciConfigIo;
use hypervisor::CpuConfigX86_64;
use hypervisor::HypervisorX86_64;
use hypervisor::IoOperation;
use hypervisor::IoParams;
use hypervisor::ProtectionType;
use hypervisor::Regs;
use hypervisor::VcpuExit;
use hypervisor::VcpuX86_64;
use hypervisor::VmCap;
use hypervisor::VmX86_64;
use resources::AddressRange;
use resources::SystemAllocator;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use x86_64::acpi;
use x86_64::arch_memory_regions;
use x86_64::bootparam;
use x86_64::cpuid::setup_cpuid;
use x86_64::init_low_memory_layout;
use x86_64::interrupts::set_lint;
use x86_64::mptable;
use x86_64::read_pci_mmio_before_32bit;
use x86_64::read_pcie_cfg_mmio;
use x86_64::regs::configure_segments_and_sregs;
use x86_64::regs::set_long_mode_msrs;
use x86_64::regs::set_mtrr_msrs;
use x86_64::regs::setup_page_tables;
use x86_64::smbios;
use x86_64::X8664arch;
use x86_64::BOOT_STACK_POINTER;
use x86_64::KERNEL_64BIT_ENTRY_OFFSET;
use x86_64::KERNEL_START_OFFSET;
use x86_64::X86_64_SCI_IRQ;
use x86_64::ZERO_PAGE_OFFSET;

enum TaggedControlTube {
    VmMemory(Tube),
    VmIrq(Tube),
    Vm(Tube),
}

/// Tests the integration of x86_64 with some hypervisor and devices setup. This test can help
/// narrow down whether boot issues are caused by the interaction between hypervisor and devices
/// and x86_64, or if they are caused by an invalid kernel or image. You can also swap in parts
/// of this function to load a real kernel and/or ramdisk.
fn simple_vm_test<H, V, Vcpu, I, FV, FI>(create_vm: FV, create_irq_chip: FI)
where
    H: HypervisorX86_64 + 'static,
    V: VmX86_64 + 'static,
    Vcpu: VcpuX86_64 + 'static,
    I: IrqChipX86_64 + 'static,
    FV: FnOnce(GuestMemory) -> (H, V),
    FI: FnOnce(V, /* vcpu_count: */ usize, Tube) -> I,
{
    /*
    0x0000000000000000:  67 89 18    mov dword ptr [eax], ebx
    0x0000000000000003:  89 D9       mov ecx, ebx
    0x0000000000000005:  89 C8       mov eax, ecx
    0x0000000000000007:  E6 FF       out 0xff, al
    */
    let code = [0x67, 0x89, 0x18, 0x89, 0xd9, 0x89, 0xc8, 0xe6, 0xff];

    // 2GB memory
    let memory_size = 0x80000000u64;
    let start_addr = GuestAddress(KERNEL_START_OFFSET + KERNEL_64BIT_ENTRY_OFFSET);

    // write to 4th page
    let write_addr = GuestAddress(0x4000);

    init_low_memory_layout(
        Some(AddressRange {
            start: 0xC000_0000,
            end: 0xCFFF_FFFF,
        }),
        Some(0x8000_0000),
    );
    // guest mem is 400 pages
    let arch_mem_regions = arch_memory_regions(memory_size, None);
    let guest_mem = GuestMemory::new_with_options(&arch_mem_regions).unwrap();

    let (hyp, mut vm) = create_vm(guest_mem.clone());
    let mut resources =
        SystemAllocator::new(X8664arch::get_system_allocator_config(&vm), None, &[])
            .expect("failed to create system allocator");
    let (irqchip_tube, device_tube) = Tube::pair().expect("failed to create irq tube");

    let mut irq_chip = create_irq_chip(vm.try_clone().expect("failed to clone vm"), 1, device_tube);

    let mmio_bus = Arc::new(Bus::new(BusType::Mmio));
    let io_bus = Arc::new(Bus::new(BusType::Io));
    let (exit_evt_wrtube, _) = Tube::directional_pair().unwrap();

    let mut control_tubes = vec![TaggedControlTube::VmIrq(irqchip_tube)];
    // Create one control socket per disk.
    let mut disk_device_tubes = Vec::new();
    let mut disk_host_tubes = Vec::new();
    let disk_count = 0;
    for _ in 0..disk_count {
        let (disk_host_tube, disk_device_tube) = Tube::pair().unwrap();
        disk_host_tubes.push(disk_host_tube);
        disk_device_tubes.push(disk_device_tube);
    }
    let (gpu_host_tube, _gpu_device_tube) = Tube::pair().unwrap();

    control_tubes.push(TaggedControlTube::VmMemory(gpu_host_tube));

    let devices = vec![];

    let (pci, pci_irqs, _pid_debug_label_map, _amls, _gpe_scope_amls) = arch::generate_pci_root(
        devices,
        &mut irq_chip,
        mmio_bus.clone(),
        GuestAddress(0),
        12,
        io_bus.clone(),
        &mut resources,
        &mut vm,
        4,
        None,
        #[cfg(feature = "swap")]
        &mut None,
    )
    .unwrap();
    let pci = Arc::new(Mutex::new(pci));
    let (pcibus_exit_evt_wrtube, _) = Tube::directional_pair().unwrap();
    let pci_bus = Arc::new(Mutex::new(PciConfigIo::new(
        pci.clone(),
        false,
        pcibus_exit_evt_wrtube,
    )));
    io_bus.insert(pci_bus, 0xcf8, 0x8).unwrap();

    X8664arch::setup_legacy_i8042_device(
        &io_bus,
        irq_chip.pit_uses_speaker_port(),
        exit_evt_wrtube.try_clone().unwrap(),
    )
    .unwrap();

    let (host_cmos_tube, cmos_tube) = Tube::pair().unwrap();
    X8664arch::setup_legacy_cmos_device(&io_bus, &mut irq_chip, cmos_tube, memory_size).unwrap();
    control_tubes.push(TaggedControlTube::Vm(host_cmos_tube));

    let mut serial_params = BTreeMap::new();

    arch::set_default_serial_parameters(&mut serial_params, false);

    X8664arch::setup_serial_devices(
        ProtectionType::Unprotected,
        &mut irq_chip,
        &io_bus,
        &serial_params,
        None,
        #[cfg(feature = "swap")]
        &mut None,
    )
    .unwrap();

    let param_args = "nokaslr acpi=noirq";

    let mut cmdline = X8664arch::get_base_linux_cmdline();

    cmdline.insert_str(param_args).unwrap();

    let params = bootparam::boot_params::default();
    // write our custom kernel code to start_addr
    guest_mem.write_at_addr(&code[..], start_addr).unwrap();
    let kernel_end = KERNEL_START_OFFSET + code.len() as u64;
    let initrd_image = None;

    // alternatively, load a real initrd and kernel from disk
    // ```
    // let initrd_image = Some(File::open("/mnt/host/source/src/avd/ramdisk.img").expect("failed to open ramdisk"));
    // let mut kernel_image = File::open("/mnt/host/source/src/avd/vmlinux.uncompressed").expect("failed to open kernel");
    // let (params, kernel_end) = X8664arch::load_kernel(&guest_mem, &mut kernel_image).expect("failed to load kernel");
    // ````

    let max_bus = (read_pcie_cfg_mmio().len().unwrap() / 0x100000 - 1) as u8;
    let (suspend_tube_send, _suspend_tube_recv) = Tube::directional_pair().unwrap();
    let mut resume_notify_devices = Vec::new();
    let acpi_dev_resource = X8664arch::setup_acpi_devices(
        pci,
        &guest_mem,
        &io_bus,
        &mut resources,
        Arc::new(Mutex::new(suspend_tube_send)),
        exit_evt_wrtube
            .try_clone()
            .expect("unable to clone exit_evt_wrtube"),
        Default::default(),
        &mut irq_chip,
        X86_64_SCI_IRQ,
        (None, None),
        &mmio_bus,
        max_bus,
        &mut resume_notify_devices,
        #[cfg(feature = "swap")]
        &mut None,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        false,
        Default::default(),
        &pci_irqs,
    )
    .unwrap();

    X8664arch::setup_system_memory(
        &guest_mem,
        &CString::new(cmdline).expect("failed to create cmdline"),
        initrd_image,
        None,
        kernel_end,
        params,
        None,
        Vec::new(),
    )
    .expect("failed to setup system_memory");

    // Note that this puts the mptable at 0x9FC00 in guest physical memory.
    mptable::setup_mptable(&guest_mem, 1, &pci_irqs).expect("failed to setup mptable");
    smbios::setup_smbios(&guest_mem, &SmbiosOptions::default(), 0).expect("failed to setup smbios");

    let mut apic_ids = Vec::new();
    acpi::create_acpi_tables(
        &guest_mem,
        1,
        X86_64_SCI_IRQ,
        0xcf9,
        6,
        &acpi_dev_resource.0,
        None,
        &mut apic_ids,
        &pci_irqs,
        read_pcie_cfg_mmio().start,
        max_bus,
        false,
    );

    let guest_mem2 = guest_mem.clone();

    let handle = thread::Builder::new()
        .name("crosvm_simple_vm_vcpu".to_string())
        .spawn(move || {
            let mut vcpu = *vm
                .create_vcpu(0)
                .expect("failed to create vcpu")
                .downcast::<Vcpu>()
                .map_err(|_| ())
                .expect("failed to downcast vcpu");

            irq_chip
                .add_vcpu(0, &vcpu)
                .expect("failed to add vcpu to irqchip");

            let cpu_config = CpuConfigX86_64::new(false, false, false, false, false, None);
            if !vm.check_capability(VmCap::EarlyInitCpuid) {
                setup_cpuid(&hyp, &irq_chip, &vcpu, 0, 1, cpu_config).unwrap();
            }

            let mut msrs = BTreeMap::new();
            set_long_mode_msrs(&mut msrs);
            set_mtrr_msrs(&mut msrs, &vm, read_pci_mmio_before_32bit().start);
            for (msr_index, value) in msrs {
                vcpu.set_msr(msr_index, value).unwrap();
            }

            let mut vcpu_regs = Regs {
                rip: start_addr.offset(),
                rsp: BOOT_STACK_POINTER,
                rsi: ZERO_PAGE_OFFSET,
                ..Default::default()
            };

            // instruction is
            // mov [eax],ebx
            // so we're writing 0x12 (the contents of ebx) to the address
            // in eax (write_addr).
            vcpu_regs.rax = write_addr.offset();
            vcpu_regs.rbx = 0x12;
            // ecx will contain 0, but after the second instruction it will
            // also contain 0x12
            vcpu_regs.rcx = 0x0;
            vcpu.set_regs(&vcpu_regs).expect("set regs failed");

            let vcpu_fpu_regs = Default::default();
            vcpu.set_fpu(&vcpu_fpu_regs).expect("set fpu regs failed");

            let mut sregs = vcpu.get_sregs().expect("get sregs failed");
            configure_segments_and_sregs(&guest_mem, &mut sregs).unwrap();
            setup_page_tables(&guest_mem, &mut sregs).unwrap();
            vcpu.set_sregs(&sregs).expect("set sregs failed");

            set_lint(0, &mut irq_chip).unwrap();

            loop {
                match vcpu.run().expect("run failed") {
                    VcpuExit::Io => {
                        vcpu.handle_io(&mut |IoParams {
                                                 address,
                                                 size,
                                                 operation: direction,
                                             }| {
                            match direction {
                                IoOperation::Write { data } => {
                                    // We consider this test to be done when this particular
                                    // one-byte port-io to port 0xff with the value of 0x12, which
                                    // was in register eax
                                    assert_eq!(address, 0xff);
                                    assert_eq!(size, 1);
                                    assert_eq!(data[0], 0x12);
                                }
                                _ => panic!("unexpected direction {:?}", direction),
                            }
                            None
                        })
                        .expect("vcpu.handle_io failed");
                        break;
                    }
                    r => {
                        panic!("unexpected exit {:?}", r);
                    }
                }
            }
            let regs = vcpu.get_regs().unwrap();
            // ecx and eax should now contain 0x12
            assert_eq!(regs.rcx, 0x12);
            assert_eq!(regs.rax, 0x12);
        })
        .unwrap();

    if let Err(e) = handle.join() {
        panic!("failed to join vcpu thread: {:?}", e);
    }

    assert_eq!(
        guest_mem2.read_obj_from_addr::<u64>(write_addr).unwrap(),
        0x12
    );
}
