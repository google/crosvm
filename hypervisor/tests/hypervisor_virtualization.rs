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
    pub mem_size: u64,
    pub initial_regs: Regs,
    pub extra_vm_setup: Option<Box<dyn Fn(&mut dyn VcpuX86_64, &mut dyn Vm) + Send>>,
    pub memory_initializations: Vec<(GuestAddress, Vec<u8>)>,
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
        }
    }

    pub fn add_memory_initialization(&mut self, addr: GuestAddress, data: Vec<u8>) {
        self.memory_initializations.push((addr, data));
    }
}

pub fn run_configurable_test<H: HypervisorTestSetup>(
    hypervisor_type: HypervisorType,
    setup: &TestSetup,
    regs_matcher: impl Fn(HypervisorType, &Regs),
    exit_matcher: impl Fn(HypervisorType, &VcpuExit, &mut dyn VcpuX86_64) -> bool,
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
        match vcpu.run().expect("run failed") {
            // Continue on external interrupt or signal
            VcpuExit::Intr => {
                println!("Got interrupt; continuing.");
                continue;
            }
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
        |_, regs| {
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
    let regs_matcher = move |_: HypervisorType, regs: &Regs| {
        assert_eq!(
            regs.rcx, 0,
            "RCX value mismatch: expected 0, found {:X}",
            regs.rcx
        )
    };

    run_tests!(setup, regs_matcher, |_, _, _| { true });
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
    let regs_matcher = |_: HypervisorType, regs: &Regs| {
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

    let regs_matcher = |_: HypervisorType, regs: &Regs| {
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

#[test]
fn test_msr_access_invalid() {
    let expected_msr_value_low = 0xFFFF;
    let expected_msr_value_high = 0xFFFF;
    let msr_index = 0xC0000080; // EFER MSR
    let setup = TestSetup {
        /*
           0:  0f 30                   wrmsr
           2:  0f 32                   rdmsr
           4:  f4                      hlt
        */
        assembly: vec![0x0F, 0x30, 0x0F, 0x32, 0xF4],
        mem_size: 0x5000,
        load_addr: GuestAddress(0x2000),
        initial_regs: Regs {
            rcx: msr_index,               // MSR index to read/write
            rax: expected_msr_value_low,  // Lower 32 bits of value to write to MSR
            rdx: expected_msr_value_high, // Higher 32 bits of value to write to MSR
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = |_: HypervisorType, regs: &Regs| {
        // Check the results of the MSR write/read
        assert_eq!(
            regs.rax, expected_msr_value_low,
            "MSR lower bits not matched."
        );
        assert_eq!(
            regs.rdx, expected_msr_value_high,
            "MSR upper bits not matched."
        );
    };

    let exit_matcher =
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => match exit {
                VcpuExit::InternalError => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
            HypervisorType::Whpx => match exit {
                VcpuExit::Mmio => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
            _ => match exit {
                VcpuExit::Shutdown => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
        };
    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_msr_access_valid() {
    let msr_index = 0xC0000080; // EFER MSR
    let lme_bit_position = 8; // Bit position for LME (Long Mode Enable)

    let setup = TestSetup {
        /*
            0:  b9 80 00 00 c0          mov    ecx,0xc0000080
            5:  0f 32                   rdmsr
            7:  0d 00 01 00 00          or     eax,0x100
            c:  0f 30                   wrmsr
            e:  f4                      hlt
        */
        assembly: vec![
            0xB9, 0x80, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x0F, 0x30,
            0xF4,
        ],
        mem_size: 0x5000,
        load_addr: GuestAddress(0x2000),
        initial_regs: Regs {
            rcx: msr_index, // MSR index to read/write
            rax: 0,         // Initialize to zero, modified by test
            rdx: 0,         // Initialize to zero, modified by test
            rflags: 0x2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| {
        if hypervisor_type == HypervisorType::Whpx {
            // Check that the LME bit is set in EAX after the operation. HAXM appears to
            // not let this bit get set.
            assert!(
                regs.rax & (1 << lme_bit_position) != 0,
                "LME bit not set in MSR EFER after modification."
            );
        }
    };

    let exit_matcher =
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Kvm => match exit {
                VcpuExit::InternalError => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
            HypervisorType::Whpx => match exit {
                VcpuExit::Mmio => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
            _ => match exit {
                VcpuExit::Shutdown => {
                    true // Break VM runloop
                }
                r => panic!("unexpected exit reason: {:?}", r),
            },
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
                    VcpuExit::Shutdown => {
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
        HypervisorType::Haxm => {}
        _ => {
            assert_eq!(regs.rip, 0x1003, "INVD; expected RIP at 0x1003");
        }
    };
    let exit_matcher =
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match hypervisor_type {
            HypervisorType::Haxm => {
                match exit {
                    VcpuExit::Shutdown => {
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
            0:  0f 01 d0                xgetbv
            3:  0f 20 e0                mov    eax,cr4
            6:  0d 00 02 00 00          or     eax,0x200  ; Set the OSXSAVE bit in CR4 (bit 9)
            b:  0f 22 e0                mov    cr4,eax
            e:  0f 01 d1                xsetbv
            11: f4                      hlt
        */
        assembly: vec![
            0x0F, 0x01, 0xD0, 0x0F, 0x20, 0xE0, 0x0D, 0x00, 0x02, 0x00, 0x00, 0x0F, 0x22, 0xE0,
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
                    VcpuExit::Shutdown => {
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
                    VcpuExit::Shutdown => {
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
                    VcpuExit::Shutdown => {
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

        let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type
        {
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
                        VcpuExit::Shutdown => {
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

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs| match hypervisor_type {
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
                    VcpuExit::Shutdown => {
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
    let regs_matcher = |_: HypervisorType, regs: &Regs| {
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
        |_, regs| {
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
