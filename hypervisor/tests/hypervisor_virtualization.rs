// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]
#![cfg(any(feature = "whpx", feature = "gvm", feature = "haxm", unix))]

use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

#[cfg(any(target_os = "android", target_os = "linux"))]
use base::MemoryMappingBuilder;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::SharedMemory;
#[cfg(feature = "gvm")]
use hypervisor::gvm::*;
#[cfg(all(windows, feature = "haxm"))]
use hypervisor::haxm::*;
#[cfg(any(target_os = "android", target_os = "linux"))]
use hypervisor::kvm::*;
#[cfg(all(windows, feature = "whpx"))]
use hypervisor::whpx::*;
#[cfg(any(target_os = "android", target_os = "linux"))]
use hypervisor::MemCacheType::CacheCoherent;
use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum HypervisorType {
    Kvm,
    Whpx,
    Haxm,
    Gvm,
}

impl std::fmt::Display for HypervisorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HypervisorType::Kvm => write!(f, "KVM"),
            HypervisorType::Whpx => write!(f, "WHPX"),
            HypervisorType::Haxm => write!(f, "HAXM"),
            HypervisorType::Gvm => write!(f, "GVM"),
        }
    }
}

pub trait HypervisorTestSetup {
    type Hypervisor: Hypervisor;
    type Vm: VmX86_64;

    fn create_vm(guest_mem: GuestMemory) -> (Self::Hypervisor, Self::Vm);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
impl HypervisorTestSetup for Kvm {
    type Hypervisor = Kvm;
    type Vm = KvmVm;

    fn create_vm(guest_mem: GuestMemory) -> (Self::Hypervisor, Self::Vm) {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    }
}

#[cfg(all(windows, feature = "whpx"))]
impl HypervisorTestSetup for Whpx {
    type Hypervisor = Whpx;
    type Vm = WhpxVm;

    fn create_vm(guest_mem: GuestMemory) -> (Self::Hypervisor, Self::Vm) {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm = WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false, None)
            .expect("failed to create vm");
        (whpx, vm)
    }
}

#[cfg(all(windows, feature = "haxm"))]
impl HypervisorTestSetup for Haxm {
    type Hypervisor = Haxm;
    type Vm = HaxmVm;

    fn create_vm(guest_mem: GuestMemory) -> (Self::Hypervisor, Self::Vm) {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    }
}

#[cfg(feature = "gvm")]
impl HypervisorTestSetup for Gvm {
    type Hypervisor = Gvm;
    type Vm = GvmVm;

    fn create_vm(guest_mem: GuestMemory) -> (Self::Hypervisor, Self::Vm) {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    }
}

pub struct TestSetup {
    pub assembly: Vec<u8>,
    pub load_addr: GuestAddress,
    pub initial_regs: Regs,
    pub extra_vm_setup: Option<Box<dyn Fn(&mut dyn VcpuX86_64, &mut dyn Vm) + Send>>,
}

impl Default for TestSetup {
    fn default() -> Self {
        TestSetup {
            assembly: Vec::new(),
            load_addr: GuestAddress(0),
            initial_regs: Regs::default(),
            extra_vm_setup: None,
        }
    }
}

// All tests get set up with 0x2000 bytes of memory.
pub fn run_configurable_test<H: HypervisorTestSetup>(
    hypervisor_type: HypervisorType,
    setup: &TestSetup,
    regs_matcher: impl Fn(HypervisorType, &Regs),
    exit_matcher: impl Fn(HypervisorType, &VcpuExit, &mut dyn VcpuX86_64) -> bool,
) {
    println!("Running test on hypervisor: {}", hypervisor_type);

    let mem_size = 0x2000;
    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0), mem_size)]).expect("failed to create guest mem");
    guest_mem
        .write_at_addr(&setup.assembly, setup.load_addr)
        .expect("failed to write to guest memory");

    let (_, mut vm) = H::create_vm(guest_mem);

    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");

    let mut sregs = vcpu.get_sregs().expect("get sregs failed");
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).expect("set sregs failed");
    vcpu.set_regs(&setup.initial_regs).expect("set regs failed");

    if let Some(ref setup_fn) = setup.extra_vm_setup {
        setup_fn(&mut *vcpu, &mut vm);
    }

    loop {
        match vcpu.run().expect("run failed") {
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            r => {
                if exit_matcher(hypervisor_type, &r, &mut *vcpu) {
                    break;
                }
                continue;
            }
        }
    }
    let final_regs = vcpu.get_regs().expect("failed to get regs");

    regs_matcher(hypervisor_type, &final_regs);
}

macro_rules! run_tests {
    ($setup:expr, $regs_matcher:expr, $exit_matcher:expr) => {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        run_configurable_test::<Kvm>(HypervisorType::Kvm, &$setup, $regs_matcher, $exit_matcher);

        #[cfg(all(windows, feature = "whpx"))]
        run_configurable_test::<Whpx>(HypervisorType::Whpx, &$setup, $regs_matcher, $exit_matcher);

        #[cfg(all(windows, feature = "haxm"))]
        run_configurable_test::<Haxm>(HypervisorType::Haxm, &$setup, $regs_matcher, $exit_matcher);

        #[cfg(feature = "gvm")]
        run_configurable_test::<Gvm>(HypervisorType::Gvm, &$setup, $regs_matcher, $exit_matcher);
    };
}

// This runs a minimal program under virtualization.
// It should require only the ability to execute instructions under virtualization, physical
// memory, the ability to get and set some guest VM registers, and intercepting HLT.
#[test]
fn test_minimal_virtualization() {
    let setup = TestSetup {
        /*
            0:  01 d8                   add    eax,ebx
            2:  f4                      hlt
        */
        assembly: vec![0x01, 0xD8, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 1,
            rbx: 2,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs| {
            assert_eq!(regs.rax, 3); // 1 + 2
            assert_eq!(regs.rip, 0x1003); // After HLT
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

#[test]
fn test_io_exit_handler() {
    // Use the OUT/IN instructions, which cause an Io exit in order to
    // read/write data using a given port.
    let load_addr = GuestAddress(0x1000);
    let setup = TestSetup {
        /*
           0:  e6 10                   out    0x10,al
           2:  e4 20                   in     al,0x20
           4:  66 01 d8                add    ax,bx
           7:  f4                      hlt
        */
        assembly: vec![0xE6, 0x10, 0xE4, 0x20, 0x66, 0x01, 0xD8, 0xF4],
        load_addr,
        initial_regs: Regs {
            rip: load_addr.offset(),
            rax: 0x34, // Only AL (lower byte of RAX) is used
            rbx: 0x42,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = |_, regs: &Regs| {
        // The result in AX should be double the initial value of AX
        // plus the initial value of BX.
        assert_eq!(regs.rax, (0x34 * 2) + 0x42);
    };

    let cached_byte = AtomicU8::new(0);
    let exit_matcher = move |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Io => {
            vcpu.handle_io(&mut |IoParams {
                                     address,
                                     size,
                                     operation,
                                 }| {
                match operation {
                    IoOperation::Read => {
                        let mut data = [0u8; 8];
                        assert_eq!(address, 0x20);
                        assert_eq!(size, 1);
                        // The original number written below will be doubled and
                        // passed back.
                        data[0] = cached_byte.load(Ordering::SeqCst) * 2;
                        Some(data)
                    }
                    IoOperation::Write { data } => {
                        assert_eq!(address, 0x10);
                        assert_eq!(size, 1);
                        assert_eq!(data[0], 0x34);
                        cached_byte.fetch_add(data[0], Ordering::SeqCst);
                        None
                    }
                }
            })
            .expect("failed to set the data");
            false // Continue VM runloop
        }
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };
    run_tests!(setup, regs_matcher, &exit_matcher);
}

// This test is similar to mmio_fetch_memory.rs (remove eventually)
// but applies to all hypervisors.
#[test]
fn test_mmio_exit_cross_page() {
    let page_size = 4096u64;
    let load_addr = GuestAddress(page_size - 1); // Last byte of the first page

    let setup = TestSetup {
        /*
        These instructions will cross the page boundary.
        0x0000000000000000:  67 88 03    mov byte ptr [ebx], al
        0x0000000000000003:  67 8A 01    mov al, byte ptr [ecx]
        0x000000000000000a:  F4          hlt
        */
        assembly: vec![0x67, 0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4],
        load_addr,
        initial_regs: Regs {
            rip: load_addr.offset(),
            rax: 0x33,
            rbx: 0x3000,
            rcx: 0x3010,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = |_, regs: &Regs| {
        assert_eq!(regs.rax, 0x66, "Should match the MMIO read bytes below");
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Mmio => {
            vcpu.handle_mmio(&mut |IoParams {
                                       address,
                                       size,
                                       operation,
                                   }| {
                match operation {
                    IoOperation::Read => {
                        match (address, size) {
                            // First MMIO read asks to load the first 8 bytes
                            // of a new execution page, when an instruction
                            // crosses page boundary.
                            // Return the rest of instructions that are
                            // supposed to be on the second page.
                            (0x1000, 8) => {
                                // Ensure this instruction is the first read
                                // in the sequence.
                                Some([0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0])
                            }
                            // Second MMIO read is a regular read from an
                            // unmapped memory (pointed to by initial EAX).
                            (0x3010, 1) => Some([0x66, 0, 0, 0, 0, 0, 0, 0]),
                            _ => {
                                panic!("invalid address({:#x})/size({})", address, size)
                            }
                        }
                    }
                    IoOperation::Write { data } => {
                        assert_eq!(address, 0x3000);
                        assert_eq!(data[0], 0x33);
                        assert_eq!(size, 1);
                        None
                    }
                }
            })
            .expect("failed to set the data");
            false // Continue VM runloop
        }
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))] // Not working for WHXP yet.
fn test_mmio_exit_readonly_memory() {
    // Read from read-only memory and then write back to it,
    // which should trigger an MMIO exit.
    let setup = TestSetup {
        /*
           0000  268A07  mov al,[es:bx]
           0003  0401    add al,0x1
           0005  268807  mov [es:bx],al
           0008  F4      hlt
        */
        assembly: vec![0x26, 0x8a, 0x07, 0x04, 0x01, 0x26, 0x88, 0x07, 0xf4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 1,
            rbx: 0,
            rflags: 2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            // Add a read-only region of memory to the VM, at address 0x5000.
            let prot_mem_size = 0x1000;
            let prot_mem =
                SharedMemory::new("test", prot_mem_size).expect("failed to create shared memory");
            let mmap_ro = MemoryMappingBuilder::new(prot_mem_size as usize)
                .from_shared_memory(&prot_mem)
                .build()
                .expect("failed to create memory mapping");
            mmap_ro
                .write_obj(0x66, 0)
                .expect("failed writing data to ro memory");
            vm.add_memory_region(
                GuestAddress(0x5000),
                Box::new(
                    MemoryMappingBuilder::new(prot_mem_size as usize)
                        .from_shared_memory(&prot_mem)
                        .build()
                        .expect("failed to create memory mapping"),
                ),
                true,
                false,
                CacheCoherent,
            )
            .expect("failed to register memory");

            // Set up segments needed by the assembly addressing above.
            let mut sregs = vcpu.get_sregs().expect("get sregs failed");
            sregs.cs.s = 1;
            sregs.cs.type_ = 0b1011;
            sregs.es.base = 0x5000;
            sregs.es.selector = 0;
            sregs.es.s = 1;
            sregs.es.type_ = 0b1011;

            vcpu.set_sregs(&sregs).expect("set sregs failed");
        })),
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Mmio => {
            vcpu.handle_mmio(&mut |IoParams {
                                       address,
                                       size,
                                       operation,
                                   }| match operation {
                IoOperation::Read => {
                    panic!("unexpected mmio read call");
                }
                IoOperation::Write { data } => {
                    assert_eq!(size, 1);
                    assert_eq!(address, 0x5000);
                    assert_eq!(data[0], 0x67);
                    None
                }
            })
            .expect("failed to set the data");
            false // Continue VM runloop
        }
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(
        setup,
        |_, regs| {
            assert_eq!(regs.rax, 0x67);
        },
        exit_matcher
    );
}
