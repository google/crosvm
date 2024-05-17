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
use hypervisor_test_macro::global_asm_data;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

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
    pub mem_size: u64,
    pub initial_regs: Regs,
    pub extra_vm_setup: Option<Box<dyn Fn(&mut dyn VcpuX86_64, &mut dyn Vm) + Send>>,
    pub memory_initializations: Vec<(GuestAddress, Vec<u8>)>,
    pub expect_run_success: bool,
}

impl Default for TestSetup {
    fn default() -> Self {
        TestSetup {
            assembly: Vec::new(),
            load_addr: GuestAddress(0),
            mem_size: 0x2000,
            initial_regs: Regs::default(),
            extra_vm_setup: None,
            memory_initializations: Vec::new(),
            expect_run_success: true,
        }
    }
}

impl TestSetup {
    pub fn new() -> Self {
        TestSetup {
            assembly: Vec::new(),
            load_addr: GuestAddress(0),
            mem_size: 0x2000,
            initial_regs: Regs::default(),
            extra_vm_setup: None,
            memory_initializations: Vec::new(),
            expect_run_success: true,
        }
    }

    pub fn add_memory_initialization(&mut self, addr: GuestAddress, data: Vec<u8>) {
        self.memory_initializations.push((addr, data));
    }
}

pub fn run_configurable_test<H: HypervisorTestSetup>(
    hypervisor_type: HypervisorType,
    setup: &TestSetup,
    regs_matcher: impl Fn(HypervisorType, &Regs, &Sregs),
    mut exit_matcher: impl FnMut(HypervisorType, &VcpuExit, &mut dyn VcpuX86_64) -> bool,
) {
    println!("Running test on hypervisor: {}", hypervisor_type);

    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0), setup.mem_size)]).expect("failed to create guest mem");

    for (addr, data) in &setup.memory_initializations {
        guest_mem
            .write_at_addr(data, *addr)
            .expect("failed to write memory initialization");
    }

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
        match vcpu.run() {
            Ok(exit) => match exit {
                VcpuExit::Intr => continue, // Handle interrupts by continuing the loop
                other_exit => {
                    if !setup.expect_run_success {
                        panic!("Expected vcpu.run() to fail, but it succeeded");
                    }
                    if exit_matcher(hypervisor_type, &other_exit, &mut *vcpu) {
                        break;
                    }
                }
            },
            Err(e) => {
                if setup.expect_run_success {
                    panic!(
                        "Expected vcpu.run() to succeed, but it failed with error: {:?}",
                        e
                    );
                } else {
                    println!("Expected failure occurred: {:?}", e);
                    break;
                }
            }
        }
    }

    let final_regs = vcpu.get_regs().expect("failed to get regs");
    let final_sregs = vcpu.get_sregs().expect("failed to get sregs");

    regs_matcher(hypervisor_type, &final_regs, &final_sregs);
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

global_asm_data!(
    test_minimal_virtualization_code,
    ".code16",
    "add ax, bx",
    "hlt"
);

// This runs a minimal program under virtualization.
// It should require only the ability to execute instructions under virtualization, physical
// memory, the ability to get and set some guest VM registers, and intercepting HLT.
#[test]
fn test_minimal_virtualization() {
    let assembly = test_minimal_virtualization_code::data().to_vec();
    let setup = TestSetup {
        assembly: assembly.clone(),
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
        |_, regs, _| {
            assert_eq!(regs.rax, 3); // 1 + 2

            // For VMEXIT caused by HLT, the hypervisor will automatically advance the rIP register.
            assert_eq!(regs.rip, 0x1000 + assembly.len() as u64);
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

    let regs_matcher = |_, regs: &Regs, _: &_| {
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

    let regs_matcher = |_, regs: &Regs, _: &_| {
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
        ..Default::default()
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
        |_, regs, _| {
            assert_eq!(regs.rax, 0x67);
        },
        exit_matcher
    );
}

#[test]
fn test_cpuid_exit_handler() {
    let setup = TestSetup {
        /*
           0:  0f a2                   cpuid
           2:  f4                      hlt
        */
        assembly: vec![0x0F, 0xA2, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 1, // CPUID input EAX=1 to get virtualization bits.
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Kvm => {}
            _ => {
                let hypervisor_bit = regs.rcx & (1 << 31) != 0;
                assert!(hypervisor_bit, "Hypervisor bit in CPUID should be set!");
                assert_eq!(regs.rip, 0x1003, "CPUID did not execute correctly.");
            }
        };

    let exit_matcher =
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Whpx => match exit {
                VcpuExit::Cpuid { entry } => {
                    println!("Got Cpuid {:?}", entry);
                    true // Break runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
            _ => match exit {
                VcpuExit::Hlt => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_control_register_access_invalid() {
    let setup = TestSetup {
        // Test setting an unused bit in addition to the Protected Mode Enable and
        // Monitor co-processor bits, which causes a triple fault and hence the
        // invalid bit should never make it to RCX.
        /*
            0:  0f 22 c0                mov    cr0,rax
            3:  0f 20 c1                mov    rcx,cr0
            6:  f4                      hlt
        */
        assembly: vec![0x0F, 0x22, 0xC0, 0x0F, 0x20, 0xC0, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 0x80000011,
            rcx: 0,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    // Matcher to check that the RAX value never made it to RCX.
    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_eq!(
            regs.rcx, 0,
            "RCX value mismatch: expected 0, found {:X}",
            regs.rcx
        )
    };

    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm | HypervisorType::Haxm => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::UnrecoverableException => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };
    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_control_register_access_valid() {
    let setup = TestSetup {
        // Set the 0th bit (Protected Mode Enable) of CR0, which should succeed.
        /*
        0:  0f 22 c0                mov    cr0, rax
        3:  0f 20 c0                mov    rax, cr0
        6:  f4                      hlt
         */
        assembly: vec![0x0F, 0x22, 0xC0, 0x0F, 0x20, 0xC0, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 0x1,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    // Matcher to check the final state of EAX after reading from CR0
    let regs_matcher = |_: HypervisorType, regs: &Regs, _: &_| {
        assert!(
            (regs.rax & 0x1) != 0,
            "CR0 value mismatch: expected the 0th bit to be set, found {:X}",
            regs.rax
        );
    };

    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm | HypervisorType::Haxm => {
                match exit {
                    VcpuExit::Hlt => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::UnrecoverableException => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };
    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_debug_register_access() {
    let setup = TestSetup {
        /*
        0:  0f 23 d0                mov    dr2,rax
        3:  0f 21 d3                mov    rbx,dr2
        6:  f4                      hlt
         */
        assembly: vec![0x0F, 0x23, 0xD0, 0x0F, 0x21, 0xD3, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 0x1234,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = |_: HypervisorType, regs: &Regs, _: &_| {
        assert_eq!(
            regs.rbx, 0x1234,
            "DR2 value mismatch: expected 0x1234, found {:X}",
            regs.rbx
        );
    };

    let exit_matcher = |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

// This test only succeeds (by failing Vcpu::Run) on haxm.
#[cfg(all(windows, feature = "haxm"))]
#[test]
fn test_msr_access_invalid() {
    let msr_index = 0xC0000080; // EFER MSR

    let setup = TestSetup {
        /*
            0:  0f 32                   rdmsr
            2:  83 c8 02                or     ax,0x2 (1st bit is reserved)
            5:  0f 30                   wrmsr
            7:  f4                      hlt
        */
        assembly: vec![0x0F, 0x32, 0x83, 0xC8, 0x02, 0x0F, 0x30, 0xF4],
        mem_size: 0x5000,
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rcx: msr_index, // MSR index to read/write
            rflags: 2,
            ..Default::default()
        },
        // This run should fail due to the invalid EFER bit being set.
        expect_run_success: false,
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(regs.rip, 0x1005); // Should stop at the wrmsr
        },
        |_, _, _| {
            /* unused */
            true
        }
    );
}

#[test]
fn test_msr_access_valid() {
    let msr_index = 0x10; // TSC MSR index

    let setup = TestSetup {
        /*
            0:  0f 32             rdmsr
            2:  83 c0 01          add    ax,1  // Increment TSC read value by 1
            5:  0f 30             wrmsr
            7:  f4                hlt
        */
        assembly: vec![0x0F, 0x32, 0x83, 0xC0, 0x01, 0x0F, 0x30, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rcx: msr_index, // MSR index for TSC
            rflags: 0x2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert!(regs.rax > 0x0, "TSC value should be >0");
        assert_eq!(regs.rip, 0x1008, "Should stop after the hlt instruction");
    };

    let exit_matcher = |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };
    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_getsec_instruction() {
    let setup = TestSetup {
        /*
           0:  0f 37                   getsec
           2:  f4                      hlt
        */
        assembly: vec![0x0F, 0x37, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Whpx => {}
            HypervisorType::Haxm => {}
            _ => {
                assert_eq!(regs.rip, 0x1000, "GETSEC; expected RIP at 0x1002");
            }
        };

    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => {
                match exit {
                    VcpuExit::InternalError => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            HypervisorType::Whpx => {
                match exit {
                    VcpuExit::Mmio => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_invd_instruction() {
    let setup = TestSetup {
        /*
           0:  0f 08                   invd
           2:  f4                      hlt
        */
        assembly: vec![0x0F, 0x08, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Haxm => {}
            _ => {
                assert_eq!(regs.rip, 0x1003, "INVD; expected RIP at 0x1003");
            }
        };
    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Haxm => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Hlt => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_xsetbv_instruction() {
    let setup = TestSetup {
        /*
            0:  0f 20 e0                mov    eax,cr4
            3:  0d 00 02 00 00          or     eax,0x200  ; Set the OSXSAVE bit in CR4 (bit 9)
            8:  0f 22 e0                mov    cr4,eax
            b:  0f 01 d0                xgetbv
            e:  0f 01 d1                xsetbv
            11: f4                      hlt
        */
        assembly: vec![
            0x0F, 0x20, 0xE0, 0x0D, 0x00, 0x02, 0x00, 0x00, 0x0F, 0x22, 0xE0, 0x0F, 0x01, 0xD0,
            0x0F, 0x01, 0xD1, 0xF4,
        ],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 1, // Set bit 0 in EAX
            rdx: 0, // XSETBV also uses EDX:EAX, must be initialized
            rcx: 0, // XCR0
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Whpx => {}
            HypervisorType::Haxm => {}
            HypervisorType::Kvm => {}
            _ => {
                assert_eq!(regs.rip, 0x100D, "XSETBV; expected RIP at 0x100D");
            }
        };

    let exit_matcher =
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => {
                match exit {
                    VcpuExit::InternalError => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            HypervisorType::Whpx => {
                match exit {
                    VcpuExit::Mmio => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_invept_instruction() {
    let setup = TestSetup {
        /*
            0:  66 0f 38 80 00          invept rax,OWORD PTR [rax]
            5:  f4                      hlt
        */
        assembly: vec![0x66, 0x0F, 0x38, 0x80, 0x00, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rax: 0x2000,
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Whpx => {}
            HypervisorType::Haxm => {}
            HypervisorType::Kvm => {}
            _ => {
                assert_eq!(regs.rip, 0x1005, "invept; expected RIP at 0x1005");
            }
        };

    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => {
                match exit {
                    VcpuExit::InternalError => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            HypervisorType::Whpx => {
                match exit {
                    VcpuExit::Mmio => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_invvpid_instruction() {
    let setup = TestSetup {
        /*
           0:  66 0f 38 81 00          invvpid rax,OWORD PTR [rax]
           5:  f4                      hlt
        */
        assembly: vec![0x66, 0x0F, 0x38, 0x81, 0x00, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 0x1500,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Haxm => {}
            HypervisorType::Kvm => {}
            _ => {
                assert_eq!(regs.rip, 0x1006, "INVVPID; expected RIP at 0x1006");
            }
        };
    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => {
                match exit {
                    VcpuExit::InternalError => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            HypervisorType::Haxm => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Hlt => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_vm_instruction_set() {
    let instructions = vec![
        (vec![0x0F, 0x01, 0xC1], 0x1000, "VMCALL"), // VMCALL
        (vec![0x66, 0x0F, 0xC7, 0x30], 0x1004, "VMCLEAR"), // VMCLEAR
        (vec![0x0F, 0x01, 0xC2], 0x1003, "VMLAUNCH"), // VMLAUNCH
        (vec![0x0F, 0xC7, 0x30], 0x1003, "VMPTRLD"), // VMPTRLD
        (vec![0x0F, 0xC7, 0x31], 0x1003, "VMPTRST"), // VMPTRST
        (vec![0x0F, 0x01, 0xC3], 0x1003, "VMRESUME"), // VMRESUME
        (vec![0x0F, 0x01, 0xC4], 0x1003, "VMXOFF"), // VMXOFF
        (vec![0x0F, 0x01, 0xC4], 0x1003, "VMXON"),  // VMXON
    ];

    for (bytes, expected_rip, name) in instructions {
        let mut assembly = bytes;
        assembly.push(0xF4); // Append HLT to each instruction set

        let setup = TestSetup {
            assembly,
            load_addr: GuestAddress(0x1000),
            initial_regs: Regs {
                rip: 0x1000,
                rflags: 2,
                ..Default::default()
            },
            ..Default::default()
        };

        let regs_matcher =
            move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
                HypervisorType::Whpx => {}
                HypervisorType::Kvm => {}
                HypervisorType::Haxm => {}
                _ => {
                    assert_eq!(
                        regs.rip, expected_rip,
                        "{}; expected RIP at {}",
                        name, expected_rip
                    );
                }
            };

        let exit_matcher =
            |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
                HypervisorType::Whpx => {
                    match exit {
                        VcpuExit::Mmio => {
                            true // Break VM runloop
                        }
                        r => panic!("unexpected exit reason: {:?}", r),
                    }
                }
                HypervisorType::Kvm => {
                    true // Break VM runloop
                }
                _ => {
                    match exit {
                        VcpuExit::Shutdown(_) => {
                            true // Break VM runloop
                        }
                        r => panic!("unexpected exit reason: {:?}", r),
                    }
                }
            };

        run_tests!(setup, regs_matcher, exit_matcher);
    }
}

#[test]
fn test_software_interrupt() {
    let setup = TestSetup {
        /*
           0:  cd 03                   int    0x3
           2:  f4                      hlt
        */
        assembly: vec![0xCD, 0x03, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher =
        move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| match hypervisor_type {
            HypervisorType::Whpx => {}
            HypervisorType::Haxm => {}
            HypervisorType::Kvm => {}
            _ => {
                assert_eq!(regs.rip, 0x1002, "Expected RIP at 0x1002");
            }
        };

    let exit_matcher =
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm | HypervisorType::Whpx => {
                match exit {
                    VcpuExit::Mmio => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
            _ => {
                match exit {
                    VcpuExit::Shutdown(_) => {
                        true // Break VM runloop
                    }
                    r => panic!("unexpected exit reason: {:?}", r),
                }
            }
        };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_rdtsc_instruction() {
    let setup = TestSetup {
        /*
            0:  0f 31                   rdtsc
            2:  f4                      hlt
        */
        assembly: vec![0x0F, 0x31, 0xF4],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    // This matcher checks that the timestamp counter has been incremented and read into EAX and EDX
    let regs_matcher = |_: HypervisorType, regs: &Regs, _: &_| {
        assert!(
            regs.rax != 0 || regs.rdx != 0,
            "RDTSC returned a zero value, which is unlikely."
        );
    };

    let exit_matcher =
        |_: HypervisorType, exit: &VcpuExit, _: &mut dyn VcpuX86_64| matches!(exit, VcpuExit::Hlt);

    run_tests!(setup, regs_matcher, exit_matcher);
}

// This tests that we can write and read GPRs to/from the VM.
#[test]
fn test_register_access() {
    let setup = TestSetup {
        /*
            0:  74 0a         jz c ; jump to hlt
            2:  93            xchg ax, bx
            3:  87 ca         xchg cx, dx
            5:  87 e5         xchg sp, bp
            7:  87 f7         xchg si, di
            9:  83 f8 01      cmp ax, 1
            12: f4            hlt
        */
        assembly: vec![
            0x74, 0x0a, 0x93, 0x87, 0xca, 0x87, 0xe5, 0x87, 0xf7, 0x83, 0xf8, 0x01, 0xf4,
        ],
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 2,
            rbx: 1,
            rcx: 4,
            rdx: 3,
            rsp: 6,
            rbp: 5,
            rsi: 8,
            rdi: 7,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(regs.rax, 1);
            assert_eq!(regs.rbx, 2);
            assert_eq!(regs.rcx, 3);
            assert_eq!(regs.rdx, 4);
            assert_eq!(regs.rsp, 5);
            assert_eq!(regs.rbp, 6);
            assert_eq!(regs.rsi, 7);
            assert_eq!(regs.rdi, 8);
            assert_ne!(regs.rflags & 0x40, 0); // zero flag is set
            assert_eq!(regs.rip, 0x100d); // after hlt
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

// Tests that the VMM can read and write CRs and they become visible in the guest.
#[test]
fn test_set_cr_vmm() {
    let asm_addr = 0x1000;
    let setup = TestSetup {
        /*
            0: 0f 20 c0     mov eax, cr0
            3: 0f 20 db     mov ebx, cr3
            6: 0f 20 e1     mov ecx, cr4
            9: f4           hlt
        */
        assembly: vec![0x0f, 0x20, 0xc0, 0x0f, 0x20, 0xdb, 0x0f, 0x20, 0xe1, 0xf4],
        load_addr: GuestAddress(asm_addr),
        initial_regs: Regs {
            rip: asm_addr,
            rflags: 2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, _| {
            let mut sregs = vcpu.get_sregs().expect("failed to get sregs");
            sregs.cr0 |= 1 << 18; // Alignment Mask; does nothing without other config bits
            sregs.cr3 = 0xfeedface; // arbitrary value; CR3 is not used in this configuration
            sregs.cr4 |= 1 << 2; // Time Stamp Disable; not relevant here
            vcpu.set_sregs(&sregs).expect("failed to set sregs");
        })),
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, sregs| {
            assert_eq!(regs.rax, sregs.cr0);
            assert_eq!(regs.rbx, sregs.cr3);
            assert_eq!(regs.rcx, sregs.cr4);
            assert_eq!(sregs.cr3, 0xfeedface);
            assert_ne!(sregs.cr0 & (1 << 18), 0);
            assert_ne!(sregs.cr4 & (1 << 2), 0);
            assert_eq!(regs.rip, asm_addr + setup.assembly.len() as u64); // after hlt
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

// Tests that the guest can read and write CRs and they become visible to the VMM.
#[test]
fn test_set_cr_guest() {
    let asm_addr = 0x1000;
    let setup = TestSetup {
        /*
            0:  0f 20 c0            mov eax, cr0
            3:  66 0d 00 00 04 00   or eax, (1 << 18)
            9:  0f 22 c0            mov cr0, eax
            c:  66 bb ce fa ed fe   mov ebx, 0xfeedface
            12: 0f 22 db            mov cr3, ebx
            15: 0f 20 e1            mov ecx, cr4
            18: 66 83 c9 04         or ecx, (1 << 2)
            1c: 0f 22 e1            mov cr4, ecx
            1f: f4                  hlt
        */
        assembly: vec![
            0x0f, 0x20, 0xc0, 0x66, 0x0d, 0x00, 0x00, 0x04, 0x00, 0x0f, 0x22, 0xc0, 0x66, 0xbb,
            0xce, 0xfa, 0xed, 0xfe, 0x0f, 0x22, 0xdb, 0x0f, 0x20, 0xe1, 0x66, 0x83, 0xc9, 0x04,
            0x0f, 0x22, 0xe1, 0xf4,
        ],
        load_addr: GuestAddress(asm_addr),
        initial_regs: Regs {
            rip: asm_addr,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, sregs| {
            assert_eq!(regs.rax, sregs.cr0);
            assert_eq!(regs.rbx, sregs.cr3);
            assert_eq!(regs.rcx, sregs.cr4);
            assert_eq!(sregs.cr3, 0xfeedface);
            assert_ne!(sregs.cr0 & (1 << 18), 0);
            assert_ne!(sregs.cr4 & (1 << 2), 0);
            assert_eq!(regs.rip, asm_addr + setup.assembly.len() as u64); // after hlt
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

mod test_minimal_interrupt_injection_code {
    use super::*;

    global_asm_data!(
        pub init,
        ".code16",
        // Set the IDT
        "lidt [0x200]",
        // Set up the stack, which will be used when CPU transfers the control to the ISR on
        // interrupt.
        "mov sp, 0x900",
        "mov eax, 902",
        // We inject our exception on this hlt command.
        "hlt",
        "mov ebx, 990",
        "hlt"
    );

    global_asm_data!(
        pub isr,
        ".code16",
        "mov eax, 888",
        "iret"
    );
}

#[test]
fn test_minimal_interrupt_injection() {
    let start_addr: u32 = 0x200;
    // Allocate exceed 0x900, where we set up our stack.
    let mem_size: u32 = 0x1000;

    let mut setup = TestSetup {
        load_addr: GuestAddress(start_addr.into()),
        initial_regs: Regs {
            rax: 0,
            rbx: 0,
            // Set RFLAGS.IF to enable interrupt.
            rflags: 2 | 0x200,
            ..Default::default()
        },
        mem_size: mem_size.into(),
        ..Default::default()
    };

    let mut cur_addr = start_addr;
    #[repr(C, packed)]
    #[derive(AsBytes)]
    // Define IDTR value
    struct Idtr {
        // The lower 2 bytes are limit.
        limit: u16,
        // The higher 4 bytes are base address.
        base_address: u32,
    }

    let idtr_size: u32 = 6;
    assert_eq!(Ok(std::mem::size_of::<Idtr>()), usize::try_from(idtr_size));
    // The limit is calculated from 256 entries timed by 4 bytes per entry.
    let idt_size = 256u16 * 4u16;
    let idtr = Idtr {
        limit: idt_size - 1,
        // The IDT right follows the IDTR.
        base_address: start_addr + idtr_size,
    };
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), idtr.as_bytes().to_vec());
    cur_addr += idtr_size;

    let idt_entry = (start_addr + idtr_size + u32::from(idt_size)).to_ne_bytes();
    // IDT entries are far pointers(CS:IP pair) to the only ISR, which locates right after the IDT.
    // We set all entries to the same ISR.
    let idt = (0..256).flat_map(|_| idt_entry).collect::<Vec<_>>();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), idt.clone());
    cur_addr += u32::try_from(idt.len()).expect("IDT size should be within u32");

    let isr_assembly = test_minimal_interrupt_injection_code::isr::data().to_vec();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_assembly.clone());
    cur_addr += u32::try_from(isr_assembly.len()).expect("ISR size should be within u32");

    let init_assembly = test_minimal_interrupt_injection_code::init::data().to_vec();
    setup.initial_regs.rip = cur_addr.into();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), init_assembly.clone());
    cur_addr += u32::try_from(init_assembly.len()).expect("init size should be within u32");
    let init_end_addr = cur_addr;

    assert!(mem_size > cur_addr);

    let mut counter = 0;
    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(regs.rip, u64::from(init_end_addr));
            assert_eq!(regs.rax, 888);
            assert_eq!(regs.rbx, 990);
        },
        |_, exit, vcpu: &mut dyn VcpuX86_64| {
            match exit {
                VcpuExit::Hlt => {
                    let regs = vcpu
                        .get_regs()
                        .expect("should retrieve registers successfully");
                    counter += 1;
                    if counter > 1 {
                        return true;
                    }
                    assert!(vcpu.ready_for_interrupt());
                    assert_eq!(regs.rax, 902);
                    assert_eq!(regs.rbx, 0);
                    // Inject an external custom interrupt.
                    vcpu.interrupt(32)
                        .expect("should be able to inject an interrupt");
                    false
                }
                r => panic!("unexpected VMEXIT reason: {:?}", r),
            }
        }
    );
}
