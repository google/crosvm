// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use devices::{IrqChipX86_64, ProtectionType};
use hypervisor::{HypervisorX86_64, VcpuExit, VcpuX86_64, VmX86_64};
use vm_memory::{GuestAddress, GuestMemory};

use super::cpuid::setup_cpuid;
use super::interrupts::set_lint;
use super::regs::{setup_fpu, setup_msrs, setup_regs, setup_sregs};
use super::X8664arch;
use super::{acpi, arch_memory_regions, bootparam, mptable, smbios};
use super::{
    BOOT_STACK_POINTER, END_ADDR_BEFORE_32BITS, KERNEL_64BIT_ENTRY_OFFSET, KERNEL_START_OFFSET,
    X86_64_SCI_IRQ, ZERO_PAGE_OFFSET,
};

use base::{Event, Tube};

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;
use std::thread;
use sync::Mutex;

use devices::PciConfigIo;

enum TaggedControlTube {
    VmMemory(Tube),
    VmIrq(Tube),
}

#[test]
fn simple_kvm_kernel_irqchip_test() {
    use devices::KvmKernelIrqChip;
    use hypervisor::kvm::*;
    simple_vm_test::<_, _, KvmVcpu, _, _, _>(
        |guest_mem| {
            let kvm = Kvm::new().expect("failed to create kvm");
            let vm = KvmVm::new(&kvm, guest_mem).expect("failed to create kvm vm");
            (kvm, vm)
        },
        |vm, vcpu_count, _| {
            KvmKernelIrqChip::new(vm, vcpu_count).expect("failed to create KvmKernelIrqChip")
        },
    );
}

#[test]
fn simple_kvm_split_irqchip_test() {
    use devices::KvmSplitIrqChip;
    use hypervisor::kvm::*;
    simple_vm_test::<_, _, KvmVcpu, _, _, _>(
        |guest_mem| {
            let kvm = Kvm::new().expect("failed to create kvm");
            let vm = KvmVm::new(&kvm, guest_mem).expect("failed to create kvm vm");
            (kvm, vm)
        },
        |vm, vcpu_count, device_tube| {
            KvmSplitIrqChip::new(vm, vcpu_count, device_tube, None)
                .expect("failed to create KvmSplitIrqChip")
        },
    );
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

    // guest mem is 400 pages
    let arch_mem_regions = arch_memory_regions(memory_size, None);
    let guest_mem = GuestMemory::new(&arch_mem_regions).unwrap();

    let mut resources = X8664arch::get_resource_allocator(&guest_mem);

    let (hyp, mut vm) = create_vm(guest_mem.clone());
    let (irqchip_tube, device_tube) = Tube::pair().expect("failed to create irq tube");

    let mut irq_chip = create_irq_chip(vm.try_clone().expect("failed to clone vm"), 1, device_tube);

    let mut mmio_bus = devices::Bus::new();
    let exit_evt = Event::new().unwrap();

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

    let (pci, pci_irqs, _pid_debug_label_map) = arch::generate_pci_root(
        devices,
        &mut irq_chip,
        &mut mmio_bus,
        &mut resources,
        &mut vm,
        4,
    )
    .unwrap();
    let pci_bus = Arc::new(Mutex::new(PciConfigIo::new(pci)));

    let mut io_bus = X8664arch::setup_io_bus(
        irq_chip.pit_uses_speaker_port(),
        exit_evt.try_clone().unwrap(),
        Some(pci_bus),
        memory_size,
    )
    .unwrap();

    let mut serial_params = BTreeMap::new();

    arch::set_default_serial_parameters(&mut serial_params);

    X8664arch::setup_serial_devices(
        ProtectionType::Unprotected,
        &mut irq_chip,
        &mut io_bus,
        &serial_params,
        None,
    )
    .unwrap();

    let param_args = "nokaslr";

    let mut cmdline = X8664arch::get_base_linux_cmdline();

    cmdline.insert_str(&param_args).unwrap();

    let params = bootparam::boot_params::default();
    // write our custom kernel code to start_addr
    guest_mem.write_at_addr(&code[..], start_addr).unwrap();
    let kernel_end = KERNEL_START_OFFSET + code.len() as u64;
    let initrd_image = None;

    // alternatively, load a real initrd and kernel from disk
    // let initrd_image = Some(File::open("/mnt/host/source/src/avd/ramdisk.img").expect("failed to open ramdisk"));
    // let mut kernel_image = File::open("/mnt/host/source/src/avd/vmlinux.uncompressed").expect("failed to open kernel");
    // let (params, kernel_end) = X8664arch::load_kernel(&guest_mem, &mut kernel_image).expect("failed to load kernel");

    let suspend_evt = Event::new().unwrap();
    let acpi_dev_resource = X8664arch::setup_acpi_devices(
        &mut io_bus,
        &mut resources,
        suspend_evt
            .try_clone()
            .expect("unable to clone suspend_evt"),
        exit_evt.try_clone().expect("unable to clone exit_evt"),
        Default::default(),
        &mut irq_chip,
        (&None, None),
        &mut mmio_bus,
    )
    .unwrap();

    X8664arch::setup_system_memory(
        &guest_mem,
        memory_size,
        &CString::new(cmdline).expect("failed to create cmdline"),
        initrd_image,
        None,
        kernel_end,
        params,
    )
    .expect("failed to setup system_memory");

    // Note that this puts the mptable at 0x9FC00 in guest physical memory.
    mptable::setup_mptable(&guest_mem, 1, pci_irqs).expect("failed to setup mptable");
    smbios::setup_smbios(&guest_mem, None).expect("failed to setup smbios");

    acpi::create_acpi_tables(&guest_mem, 1, X86_64_SCI_IRQ, acpi_dev_resource.0);

    let guest_mem2 = guest_mem.clone();

    let handle = thread::Builder::new()
        .name("crosvm_simple_vm_vcpu".to_string())
        .spawn(move || {
            let vcpu = *vm
                .create_vcpu(0)
                .expect("failed to create vcpu")
                .downcast::<Vcpu>()
                .map_err(|_| ())
                .expect("failed to downcast vcpu");

            irq_chip
                .add_vcpu(0, &vcpu)
                .expect("failed to add vcpu to irqchip");

            setup_cpuid(&hyp, &irq_chip, &vcpu, 0, 1, false).unwrap();
            setup_msrs(&vcpu, END_ADDR_BEFORE_32BITS).unwrap();

            setup_regs(
                &vcpu,
                start_addr.offset() as u64,
                BOOT_STACK_POINTER as u64,
                ZERO_PAGE_OFFSET as u64,
            )
            .unwrap();

            let mut vcpu_regs = vcpu.get_regs().unwrap();
            // instruction is
            // mov [eax],ebx
            // so we're writing 0x12 (the contents of ebx) to the address
            // in eax (write_addr).
            vcpu_regs.rax = write_addr.offset() as u64;
            vcpu_regs.rbx = 0x12;
            // ecx will contain 0, but after the second instruction it will
            // also contain 0x12
            vcpu_regs.rcx = 0x0;
            vcpu.set_regs(&vcpu_regs).expect("set regs failed");

            setup_fpu(&vcpu).unwrap();
            setup_sregs(&guest_mem, &vcpu).unwrap();
            set_lint(0, &mut irq_chip).unwrap();

            let run_handle = vcpu.take_run_handle(None).unwrap();
            loop {
                match vcpu.run(&run_handle).expect("run failed") {
                    VcpuExit::IoOut {
                        port: 0xff,
                        size,
                        data,
                    } => {
                        // We consider this test to be done when this particular
                        // one-byte port-io to port 0xff with the value of 0x12, which was in
                        // register eax
                        assert_eq!(size, 1);
                        assert_eq!(data[0], 0x12);
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
