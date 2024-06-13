// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]
#![cfg(any(feature = "whpx", feature = "gvm", feature = "haxm", unix))]

use core::mem;
use std::cell::RefCell;
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

const FLAGS_IF_BIT: u64 = 0x200;

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

    /// Whether the `exit_matcher` should recieve [`VcpuExit::Intr`]. Default to `false`.
    ///
    /// Hypervisors may occasinally receive [`VcpuExit::Intr`] if external interrupt intercept is
    /// enabled. In such case, we should proceed to the next VCPU run to handle it. HAXM doesn't
    /// distinguish between [`VcpuExit::Intr`] and [`VcpuExit::IrqWindowOpen`], so it may be
    /// necessary to intercept [`VcpuExit::Intr`] for testing
    /// [`VcpuX86_64::set_interrupt_window_requested`].
    pub intercept_intr: bool,
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
            intercept_intr: false,
        }
    }
}

impl TestSetup {
    pub fn new() -> Self {
        Default::default()
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
                // Handle interrupts by continuing the loop
                VcpuExit::Intr if !setup.intercept_intr => continue,
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

const GDT_OFFSET: u64 = 0x1500;
const IDT_OFFSET: u64 = 0x1528;

pub fn configure_long_mode_memory(vm: &mut dyn Vm) -> Segment {
    // Condensed version of the function in x86_64\src\gdt.rs
    pub fn segment_from_gdt(entry: u64, table_index: u8) -> Segment {
        Segment {
            base: (((entry) & 0xFF00000000000000) >> 32)
                | (((entry) & 0x000000FF00000000) >> 16)
                | (((entry) & 0x00000000FFFF0000) >> 16),
            limit: ((((entry) & 0x000F000000000000) >> 32) | ((entry) & 0x000000000000FFFF)) as u32,
            selector: (table_index * 8) as u16,
            type_: ((entry & 0x00000F0000000000) >> 40) as u8,
            present: ((entry & 0x0000800000000000) >> 47) as u8,
            dpl: ((entry & 0x0000600000000000) >> 45) as u8,
            db: ((entry & 0x0040000000000000) >> 54) as u8,
            s: ((entry & 0x0000100000000000) >> 44) as u8,
            l: ((entry & 0x0020000000000000) >> 53) as u8,
            g: ((entry & 0x0080000000000000) >> 55) as u8,
            avl: ((entry & 0x0010000000000000) >> 52) as u8,
        }
    }

    let guest_mem = vm.get_memory();

    assert!(
        guest_mem.range_overlap(GuestAddress(0x1500), GuestAddress(0xc000)),
        "Long-mode setup requires 0x1500-0xc000 to be mapped in the guest."
    );

    const PRESENT: u8 = 1 << 7;
    const NOT_SYS: u8 = 1 << 4;
    const EXEC: u8 = 1 << 3;
    const RW: u8 = 1 << 1;
    const ACCESSED: u8 = 1 << 0;

    const GRAN_4K: u8 = 1 << 7;
    const LONG_MODE: u8 = 1 << 5;

    // Setup GDT
    let gdt: Vec<u8> = vec![
        // Null descriptor
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Null descriptor
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Code segment descriptor
        0xFF, // Limit & Base (low, bits 0-15)
        0xFF,
        0x00,
        0x00,
        0x00,                                     // Base (mid, bits 16-23)
        PRESENT | NOT_SYS | EXEC | RW | ACCESSED, // Access byte
        GRAN_4K | LONG_MODE | 0x0F,               // Flags & Limit (high)
        0x00,                                     // Base (high)
    ];

    let gdt_addr = GuestAddress(GDT_OFFSET);
    guest_mem
        .write_at_addr(&gdt, gdt_addr)
        .expect("Failed to write GDT entry to guest memory");

    // Convert the GDT entries to a vector of u64
    let gdt_entries: Vec<u64> = gdt
        .chunks(8)
        .map(|chunk| {
            let mut array = [0u8; 8];
            array.copy_from_slice(chunk);
            u64::from_le_bytes(array)
        })
        .collect();

    let code_seg = segment_from_gdt(gdt_entries[2], 2);

    // Setup IDT
    let idt_addr = GuestAddress(IDT_OFFSET);
    let idt_entry: u64 = 0; // Empty IDT
    let idt_entry_bytes = idt_entry.to_le_bytes();
    guest_mem
        .write_at_addr(&idt_entry_bytes, idt_addr)
        .expect("failed to write IDT entry to guest memory");

    // Setup paging
    let pml4_addr = GuestAddress(0x9000);
    let pdpte_addr = GuestAddress(0xa000);
    let pde_addr = GuestAddress(0xb000);

    // Pointing to PDPTE with present and RW flags
    guest_mem
        .write_at_addr(&(pdpte_addr.0 | 3).to_le_bytes(), pml4_addr)
        .expect("failed to write PML4 entry");

    // Pointing to PD with present and RW flags
    guest_mem
        .write_at_addr(&(pde_addr.0 | 3).to_le_bytes(), pdpte_addr)
        .expect("failed to write PDPTE entry");

    for i in 0..512 {
        // Each 2MiB page present and RW
        let pd_entry_bytes = ((i << 21) | 0x83u64).to_le_bytes();
        guest_mem
            .write_at_addr(
                &pd_entry_bytes,
                pde_addr.unchecked_add(i * mem::size_of::<u64>() as u64),
            )
            .expect("Failed to write PDE entry");
    }

    code_seg
}

pub fn enter_long_mode(vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm) {
    let code_seg = configure_long_mode_memory(vm);

    let mut sregs = vcpu.get_sregs().expect("failed to get sregs");

    let pml4_addr = GuestAddress(0x9000);

    sregs.gdt.base = GDT_OFFSET;
    sregs.gdt.limit = 0xFFFF;

    sregs.idt.base = IDT_OFFSET;
    sregs.idt.limit = 0xFFFF;

    sregs.cs = code_seg;

    // Long mode
    sregs.cr0 |= 0x1 | 0x80000000; // PE & PG
    sregs.efer |= 0x100 | 0x400; // LME & LMA (Must be auto-enabled with CR0_PG)
    sregs.cr3 = pml4_addr.offset();
    sregs.cr4 |= 0x80 | 0x20; // PGE & PAE

    vcpu.set_sregs(&sregs).expect("failed to set sregs");
}

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

global_asm_data!(
    test_io_exit_handler_code,
    ".code16",
    "out 0x10, al",
    "in al, 0x20",
    "add ax, bx",
    "hlt",
);

#[test]
fn test_io_exit_handler() {
    // Use the OUT/IN instructions, which cause an Io exit in order to
    // read/write data using a given port.
    let load_addr = GuestAddress(0x1000);
    let setup = TestSetup {
        assembly: test_io_exit_handler_code::data().to_vec(),
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

global_asm_data!(
    test_mmio_exit_cross_page_code,
    ".code16",
    "mov byte ptr [ebx], al",
    "mov al, byte ptr [ecx]",
    "hlt",
);

// This test is similar to mmio_fetch_memory.rs (remove eventually)
// but applies to all hypervisors.
#[test]
fn test_mmio_exit_cross_page() {
    let page_size = 4096u64;
    let load_addr = GuestAddress(page_size - 1); // Last byte of the first page

    let setup = TestSetup {
        assembly: test_mmio_exit_cross_page_code::data().to_vec(),
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

global_asm_data!(
    test_mmio_exit_readonly_memory_code,
    ".code16",
    "mov al,BYTE PTR es:[bx]",
    "add al, 0x1",
    "mov BYTE PTR es:[bx], al",
    "hlt",
);

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))] // Not working for WHXP yet.
fn test_mmio_exit_readonly_memory() {
    // Read from read-only memory and then write back to it,
    // which should trigger an MMIO exit.
    let setup = TestSetup {
        assembly: test_mmio_exit_readonly_memory_code::data().to_vec(),
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

#[rustfmt::skip::macros(global_asm_data)]
global_asm_data!(
    test_cpuid_exit_handler_code,
    ".code16",
    "cpuid",
    "hlt",
);

#[test]
fn test_cpuid_exit_handler() {
    let setup = TestSetup {
        assembly: test_cpuid_exit_handler_code::data().to_vec(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 1, // CPUID input EAX=1 to get virtualization bits.
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = move |hypervisor_type: HypervisorType, regs: &Regs, _: &_| {
        if hypervisor_type == HypervisorType::Haxm {
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

global_asm_data!(
    test_control_register_access_invalid_code,
    ".code16",
    // Test setting an unused bit in addition to the Protected Mode Enable and Monitor co-processor
    // bits, which causes a triple fault and hence the invalid bit should never make it to RCX.
    "mov cr0, eax",
    "mov ecx, cr0",
    "hlt",
);

#[test]
fn test_control_register_access_invalid() {
    let setup = TestSetup {
        assembly: test_control_register_access_invalid_code::data().to_vec(),
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

global_asm_data!(
    test_control_register_access_valid_code,
    // Set the 0th bit (Protected Mode Enable) of CR0, which should succeed.
    ".code16",
    "mov cr0, eax",
    "mov eax, cr0",
    "hlt",
);

#[test]
fn test_control_register_access_valid() {
    let setup = TestSetup {
        assembly: test_control_register_access_invalid_code::data().to_vec(),
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

    let exit_matcher = move |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };
    run_tests!(setup, regs_matcher, exit_matcher);
}

global_asm_data!(
    test_debug_register_access_code,
    ".code16",
    "mov dr2, eax",
    "mov ebx, dr2",
    "hlt",
);

#[test]
fn test_debug_register_access() {
    let setup = TestSetup {
        assembly: test_debug_register_access_code::data().to_vec(),
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

global_asm_data!(
    test_msr_access_valid_code,
    ".code16",
    "rdmsr",
    "add ax, 1",
    "wrmsr",
    "hlt",
);

#[test]
fn test_msr_access_valid() {
    let msr_index = 0x10; // TSC MSR index

    let setup = TestSetup {
        assembly: test_msr_access_valid_code::data().to_vec(),
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

#[rustfmt::skip::macros(global_asm_data)]
global_asm_data!(
    test_getsec_instruction_code,
    ".code16",
    "getsec",
    "hlt",
);

#[test]
fn test_getsec_instruction() {
    let setup = TestSetup {
        assembly: test_getsec_instruction_code::data().to_vec(),
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

#[rustfmt::skip::macros(global_asm_data)]
global_asm_data!(
    test_invd_instruction_code,
    ".code16",
    "invd",
    "hlt",
);

#[test]
fn test_invd_instruction() {
    let setup = TestSetup {
        assembly: test_invd_instruction_code::data().to_vec(),
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

global_asm_data!(
    test_xsetbv_instruction_code,
    ".code16",
    "mov eax, cr4",
    // Set the OSXSAVE bit in CR4 (bit 9)
    "or ax, 0x200",
    "mov cr4, eax",
    "xgetbv",
    "xsetbv",
    "hlt",
);

#[test]
fn test_xsetbv_instruction() {
    let setup = TestSetup {
        assembly: test_xsetbv_instruction_code::data().to_vec(),
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

global_asm_data!(
    test_invept_instruction_code,
    ".code16",
    "invept eax, [eax]",
    "hlt",
);

// TODO(b/342183625): invept instruction is not valid in real mode. Reconsider how we should write
// this test.
#[test]
fn test_invept_instruction() {
    let setup = TestSetup {
        assembly: test_invept_instruction_code::data().to_vec(),
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

global_asm_data!(
    test_invvpid_instruction_code,
    ".code16",
    "invvpid eax, [eax]",
    "hlt",
);

// TODO(b/342183625): invvpid instruction is not valid in real mode. Reconsider how we should write
// this test.
#[test]
fn test_invvpid_instruction() {
    let setup = TestSetup {
        assembly: test_invvpid_instruction_code::data().to_vec(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rax: 0x1500,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let regs_matcher = move |_, regs: &Regs, _: &_| {
        assert_eq!(regs.rip, 0x1000, "INVVPID; expected RIP at 0x1000");
    };

    let exit_matcher = move |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Mmio | VcpuExit::Shutdown(_) | VcpuExit::InternalError => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
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

#[rustfmt::skip::macros(global_asm_data)]
global_asm_data!(
    test_software_interrupt_code,
    "int 0x80",
    "hlt",
);

#[test]
fn test_software_interrupt() {
    let start_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_software_interrupt_code::data().to_vec(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: start_addr,
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
                let expect_rip_addr = start_addr
                    + u64::try_from(test_software_interrupt_code::data().len())
                        .expect("the code length should within the range of u64");
                assert_eq!(
                    regs.rip, expect_rip_addr,
                    "Expected RIP at {:#x}",
                    expect_rip_addr
                );
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

#[rustfmt::skip::macros(global_asm_data)]
global_asm_data!(
    test_rdtsc_instruction_code,
    ".code16",
    "rdtsc",
    "hlt",
);

#[test]
fn test_rdtsc_instruction() {
    let setup = TestSetup {
        assembly: test_rdtsc_instruction_code::data().to_vec(),
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

global_asm_data!(
    test_register_access_code,
    ".code16",
    "xchg ax, bx",
    "xchg cx, dx",
    "xchg sp, bp",
    "xchg si, di",
    "hlt",
);

// This tests that we can write and read GPRs to/from the VM.
#[test]
fn test_register_access() {
    let start_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_register_access_code::data().to_vec(),
        load_addr: GuestAddress(start_addr),
        initial_regs: Regs {
            rip: start_addr,
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
            assert_eq!(
                regs.rip,
                start_addr + test_register_access_code::data().len() as u64
            );
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

global_asm_data!(
    test_flags_register_code,
    ".code16",
    "jnz fin",
    "test ax, ax",
    "fin:",
    "hlt",
);

// This tests that we can get/set the flags register from the VMM.
#[test]
fn test_flags_register() {
    let start_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_flags_register_code::data().to_vec(),
        load_addr: GuestAddress(start_addr),
        initial_regs: Regs {
            rip: start_addr,
            rax: 0xffffffff,
            rflags: 0x42, // zero flag set, sign flag clear
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(regs.rflags & 0x40, 0); // zero flag is clear
            assert_ne!(regs.rflags & 0x80, 0); // sign flag is set
            assert_eq!(
                regs.rip,
                start_addr + test_flags_register_code::data().len() as u64
            );
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

global_asm_data!(
    test_vmm_set_segs_code,
    ".code16",
    "mov ax, ds:0",
    "mov bx, es:0",
    "mov cx, fs:0",
    "mov dx, gs:0",
    "mov sp, ss:0",
    "hlt",
);

// This tests that the VMM can set segment registers and have them used by the VM.
#[test]
fn test_vmm_set_segs() {
    let start_addr = 0x1000;
    let data_addr = 0x2000;
    let setup = TestSetup {
        assembly: test_vmm_set_segs_code::data().to_vec(),
        load_addr: GuestAddress(start_addr),
        mem_size: 0x4000,
        initial_regs: Regs {
            rip: start_addr,
            rflags: 0x42,
            ..Default::default()
        },
        // simple memory pattern where the value of a byte is (addr - data_addr + 1)
        memory_initializations: vec![(GuestAddress(data_addr), (1..=32).collect())],
        extra_vm_setup: Some(Box::new(move |vcpu: &mut dyn VcpuX86_64, _| {
            let mut sregs = vcpu.get_sregs().expect("failed to get sregs");
            sregs.ds.base = data_addr;
            sregs.ds.selector = 0;
            sregs.es.base = data_addr + 4;
            sregs.es.selector = 0;
            sregs.fs.base = data_addr + 8;
            sregs.fs.selector = 0;
            sregs.gs.base = data_addr + 12;
            sregs.gs.selector = 0;
            sregs.ss.base = data_addr + 16;
            sregs.ss.selector = 0;
            vcpu.set_sregs(&sregs).expect("failed to set sregs");
        })),
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, sregs| {
            assert_eq!(sregs.ds.base, data_addr);
            assert_eq!(sregs.es.base, data_addr + 4);
            assert_eq!(sregs.fs.base, data_addr + 8);
            assert_eq!(sregs.gs.base, data_addr + 12);
            assert_eq!(sregs.ss.base, data_addr + 16);

            // ax was loaded from ds:0, which has offset 0, so is [1, 2]
            assert_eq!(regs.rax, 0x0201);
            // bx was loaded from es:0, which has offset 4, so is [5, 6]
            assert_eq!(regs.rbx, 0x0605);
            // cx was loaded from fs:0, which has offset 8, so is [9, 10]
            assert_eq!(regs.rcx, 0x0a09);
            // dx was loaded from gs:0, which has offset 12, so is [13, 14]
            assert_eq!(regs.rdx, 0x0e0d);
            // sp was loaded from ss:0, which has offset 16, so is [17, 18]
            assert_eq!(regs.rsp, 0x1211);

            let expect_rip_addr = start_addr
                + u64::try_from(test_vmm_set_segs_code::data().len())
                    .expect("the code length should within the range of u64");
            assert_eq!(
                regs.rip, expect_rip_addr,
                "Expected RIP at {:#x}",
                expect_rip_addr
            );
        },
        |_, exit, _| matches!(exit, VcpuExit::Hlt)
    );
}

global_asm_data!(
    test_set_cr_vmm_code,
    ".code16",
    "mov eax, cr0",
    "mov ebx, cr3",
    "mov ecx, cr4",
    "hlt",
);

// Tests that the VMM can read and write CRs and they become visible in the guest.
#[test]
fn test_set_cr_vmm() {
    let asm_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_set_cr_vmm_code::data().to_vec(),
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

global_asm_data!(
    test_set_cr_guest_code,
    ".code16",
    "mov eax, cr0",
    "or eax, (1 << 18)",
    "mov cr0, eax",
    "mov ebx, 0xfeedface",
    "mov cr3, ebx",
    "mov ecx, cr4",
    "or ecx, (1 << 2)",
    "mov cr4, ecx",
    "hlt",
);

// Tests that the guest can read and write CRs and they become visible to the VMM.
#[test]
fn test_set_cr_guest() {
    let asm_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_set_cr_guest_code::data().to_vec(),
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

#[repr(C, packed)]
#[derive(AsBytes)]
// Define IDTR value
struct Idtr {
    // The lower 2 bytes are limit.
    limit: u16,
    // The higher 4 bytes are base address.
    base_address: u32,
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
            rflags: 2 | FLAGS_IF_BIT,
            ..Default::default()
        },
        mem_size: mem_size.into(),
        ..Default::default()
    };

    let mut cur_addr = start_addr;

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

mod test_multiple_interrupt_injection_code {
    use super::*;

    global_asm_data!(
        pub init,
        ".code16",
        // Set the IDT
        "lidt [0x200]",
        // Set up the stack, which will be used when CPU transfers the control to the ISR on
        // interrupt.
        "mov esp, 0x900",
        "mov eax, 1",
        "mov ebx, 2",
        "mov ecx, 3",
        "mov edx, 4",
        // We inject our interrupts on this hlt command.
        "hlt",
        "mov edx, 281",
        "hlt",
    );

    global_asm_data!(
        pub isr_intr_32,
        ".code16",
        "mov eax, 32",
        "iret",
    );

    global_asm_data!(
        pub isr_intr_33,
        ".code16",
        "mov ebx, 33",
        "iret",
    );

    global_asm_data!(
        pub isr_default,
        ".code16",
        "mov ecx, 761",
        "iret",
    );
}

#[test]
fn test_multiple_interrupt_injection() {
    let start_addr: u32 = 0x200;
    // Allocate exceed 0x900, where we set up our stack.
    let mem_size: u32 = 0x1000;

    let mut setup = TestSetup {
        load_addr: GuestAddress(start_addr.into()),
        initial_regs: Regs {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            // Set RFLAGS.IF to enable interrupt.
            rflags: 2 | FLAGS_IF_BIT,
            ..Default::default()
        },
        mem_size: mem_size.into(),
        ..Default::default()
    };

    let mut cur_addr = start_addr;

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

    let isr_intr_32_assembly = test_multiple_interrupt_injection_code::isr_intr_32::data().to_vec();
    let isr_intr_33_assembly = test_multiple_interrupt_injection_code::isr_intr_33::data().to_vec();
    let isr_default_assembly = test_multiple_interrupt_injection_code::isr_default::data().to_vec();
    // The ISR for intr 32 right follows the IDT.
    let isr_intr_32_addr = cur_addr + u32::from(idt_size);
    // The ISR for intr 33 right follows the ISR for intr 32.
    let isr_intr_33_addr = isr_intr_32_addr
        + u32::try_from(isr_intr_32_assembly.len())
            .expect("the size of the ISR for intr 32 should be within the u32 range");
    // The ISR for other interrupts right follows the ISR for intr 33.
    let isr_default_addr = isr_intr_33_addr
        + u32::try_from(isr_intr_33_assembly.len())
            .expect("the size of the ISR for intr 33 should be within the u32 range");

    // IDT entries are far pointers(CS:IP pair) to the correspondent ISR.
    let idt = (0..256)
        .map(|intr_vec| match intr_vec {
            32 => isr_intr_32_addr,
            33 => isr_intr_33_addr,
            _ => isr_default_addr,
        })
        .flat_map(u32::to_ne_bytes)
        .collect::<Vec<_>>();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), idt.clone());
    assert_eq!(idt.len(), usize::from(idt_size));
    cur_addr += u32::try_from(idt.len()).expect("IDT size should be within u32");

    assert_eq!(cur_addr, isr_intr_32_addr);
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_intr_32_assembly.clone());
    cur_addr += u32::try_from(isr_intr_32_assembly.len()).expect("ISR size should be within u32");

    assert_eq!(cur_addr, isr_intr_33_addr);
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_intr_33_assembly.clone());
    cur_addr += u32::try_from(isr_intr_33_assembly.len()).expect("ISR size should be within u32");

    assert_eq!(cur_addr, isr_default_addr);
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_default_assembly.clone());
    cur_addr += u32::try_from(isr_default_assembly.len()).expect("ISR size should be within u32");

    let init_assembly = test_multiple_interrupt_injection_code::init::data().to_vec();
    setup.initial_regs.rip = cur_addr.into();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), init_assembly.clone());
    cur_addr += u32::try_from(init_assembly.len()).expect("init size should be within u32");
    let init_end_addr = cur_addr;

    assert!(mem_size > cur_addr);

    let mut counter = 0;
    run_tests!(
        setup,
        |hypervisor_type, regs, _| {
            // Different hypervisors behave differently on how the first injected exception should
            // handled: for WHPX and KVM, the later injected interrupt overrides the earlier
            // injected interrupt, while for HAXM, both interrupts are marked as pending.
            match hypervisor_type {
                HypervisorType::Haxm => assert_eq!(regs.rax, 32),
                _ => assert_eq!(regs.rax, 1),
            }

            assert_eq!(regs.rip, u64::from(init_end_addr));
            assert_eq!(regs.rbx, 33);
            assert_eq!(regs.rcx, 3);
            assert_eq!(regs.rdx, 281);
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
                    assert_eq!(regs.rax, 1);
                    assert_eq!(regs.rbx, 2);
                    assert_eq!(regs.rcx, 3);
                    assert_eq!(regs.rdx, 4);
                    // Inject external custom interrupts.
                    assert!(vcpu.ready_for_interrupt());
                    vcpu.interrupt(32)
                        .expect("should be able to inject an interrupt");
                    assert!(vcpu.ready_for_interrupt());
                    vcpu.interrupt(33)
                        .expect("should be able to inject an interrupt");
                    false
                }
                r => panic!("unexpected VMEXIT reason: {:?}", r),
            }
        }
    );
}

mod test_interrupt_ready_when_not_interruptible_code {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum Instrumentation {
        BeforeMovSs,
        AfterMovSs,
        AfterAfterMovSs,
        BeforeSti,
        AfterSti,
        AfterAfterSti,
        InIsr,
    }

    impl From<u64> for Instrumentation {
        fn from(value: u64) -> Self {
            match value {
                0x10 => Instrumentation::BeforeMovSs,
                0x20 => Instrumentation::AfterMovSs,
                0x30 => Instrumentation::AfterAfterMovSs,
                0x40 => Instrumentation::BeforeSti,
                0x50 => Instrumentation::AfterSti,
                0x60 => Instrumentation::AfterAfterSti,
                0xf0 => Instrumentation::InIsr,
                _ => panic!("Unknown instrumentation IO port: {}", value),
            }
        }
    }

    // We use port IO to trigger the VMEXIT instead of MMIO, because access to out of bound memory
    // doesn't trigger MMIO VMEXIT on WHPX under simple real-mode set up.
    global_asm_data!(
        pub init,
        ".code16",
        // Set up the stack, which will be used when CPU transfers the control to the ISR on
        // interrupt.
        "mov sp, 0x1900",
        // Set the IDT.
        "lidt [0x200]",
        // Load the ss register, so that the later mov ss instruction is actually a no-op.
        "mov ax, ss",
        "out 0x10, ax",
        // Hypervisors shouldn't allow interrupt injection right after the mov ss instruction.
        "mov ss, ax",
        "out 0x20, ax",
        // On WHPX we need some other instructions to bring the interuptibility back to normal.
        // While this is not needed for other hypervisors, we add this instruction unconditionally.
        "nop",
        "out 0x30, ax",
        "out 0x40, ax",
        // Test hypervisors' interruptibilities right after sti instruction when FLAGS.IF is
        // cleared.
        "cli",
        "sti",
        "out 0x50, ax",
        // On WHPX we need some other instructions to bring the interuptibility back to normal.
        // While this is not needed for other hypervisors, we add this instruction unconditionally.
        "nop",
        "out 0x60, ax",
        "hlt",
    );

    global_asm_data!(
        pub isr,
        ".code16",
        "out 0xf0, ax",
        "iret",
    );
}

// Physical x86 processor won't allow interrupt to be injected after mov ss or sti, while VM can.
#[test]
fn test_interrupt_ready_when_normally_not_interruptible() {
    use test_interrupt_ready_when_not_interruptible_code::Instrumentation;

    let start_addr: u32 = 0x200;
    // Allocate exceed 0x1900, where we set up our stack.
    let mem_size: u32 = 0x2000;

    let mut setup = TestSetup {
        load_addr: GuestAddress(start_addr.into()),
        initial_regs: Regs {
            rax: 0,
            rbx: 0,
            // Set RFLAGS.IF to enable interrupt.
            rflags: 2 | 0x202,
            ..Default::default()
        },
        mem_size: mem_size.into(),
        ..Default::default()
    };

    let mut cur_addr = start_addr;

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

    let isr_assembly = test_interrupt_ready_when_not_interruptible_code::isr::data().to_vec();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_assembly.clone());
    cur_addr += u32::try_from(isr_assembly.len()).expect("ISR size should be within u32");

    let init_assembly = test_interrupt_ready_when_not_interruptible_code::init::data().to_vec();
    setup.initial_regs.rip = cur_addr.into();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), init_assembly.clone());
    cur_addr += u32::try_from(init_assembly.len()).expect("init size should be within u32");

    assert!(mem_size > cur_addr);

    // This helps us check the interruptibility under different situations.
    let interruptibility_traces = RefCell::<Vec<_>>::default();
    // This helps us check when the interrupt actually delivers.
    let instrumentation_traces = RefCell::<Vec<_>>::default();

    run_tests!(
        setup,
        |_, regs, _| {
            use Instrumentation::*;
            assert_eq!(
                *interruptibility_traces.borrow(),
                [
                    (BeforeMovSs, true),
                    // Hypervisors don't allow interrupt injection right after mov ss.
                    (AfterMovSs, false),
                    (AfterAfterMovSs, true),
                    (BeforeSti, true),
                    // Hypervisors don't allow interrupt injection right after sti when FLAGS.IF is
                    // not set.
                    (AfterSti, false),
                    (AfterAfterSti, true)
                ]
            );
            // Hypervisors always deliver the interrupt right after we inject it in the next VCPU
            // run.
            assert_eq!(
                *instrumentation_traces.borrow(),
                [
                    BeforeMovSs,
                    InIsr,
                    AfterMovSs,
                    AfterAfterMovSs,
                    InIsr,
                    BeforeSti,
                    InIsr,
                    AfterSti,
                    AfterAfterSti,
                    InIsr,
                ]
            );
            assert_eq!(regs.rip, u64::from(cur_addr));
        },
        |_, exit, vcpu: &mut dyn VcpuX86_64| {
            match exit {
                VcpuExit::Io => {
                    let ready_for_interrupt = vcpu.ready_for_interrupt();
                    let mut should_inject_interrupt = ready_for_interrupt;
                    vcpu.handle_io(&mut |io_params| {
                        let instrumentation = Instrumentation::from(io_params.address);
                        match instrumentation {
                            Instrumentation::InIsr => {
                                // Only inject interrupt outside ISR.
                                should_inject_interrupt = false;
                            }
                            _ => {
                                // Only the interuptibility outside the ISR is important for this
                                // test.
                                interruptibility_traces
                                    .borrow_mut()
                                    .push((instrumentation, ready_for_interrupt));
                            }
                        }
                        instrumentation_traces.borrow_mut().push(instrumentation);
                        // We are always handling out IO port, so no data to return.
                        None
                    })
                    .expect("should handle IO successfully");
                    if should_inject_interrupt {
                        vcpu.interrupt(32)
                            .expect("interrupt injection should succeed when ready for interrupt");
                    }
                    false
                }
                VcpuExit::Hlt => true,
                r => panic!("unexpected VMEXIT reason: {:?}", r),
            }
        }
    );
}

global_asm_data!(
    test_interrupt_ready_when_interrupt_enable_flag_not_set_code,
    ".code16",
    "cli",
    // We can't use hlt for VMEXIT, because HAXM unconditionally allows interrupt injection for
    // hlt.
    "out 0x10, ax",
    "sti",
    // nop is necessary to avoid the one instruction ineterrupt disable window for sti when
    // FLAGS.IF is not set.
    "nop",
    "out 0x20, ax",
    "hlt",
);

#[test]
fn test_interrupt_ready_when_interrupt_enable_flag_not_set() {
    let assembly = test_interrupt_ready_when_interrupt_enable_flag_not_set_code::data().to_vec();
    let setup = TestSetup {
        assembly: assembly.clone(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            // For VMEXIT caused by HLT, the hypervisor will automatically advance the rIP register.
            assert_eq!(regs.rip, 0x1000 + assembly.len() as u64);
        },
        |_, exit, vcpu| {
            match exit {
                VcpuExit::Io => {
                    let mut addr = 0;
                    vcpu.handle_io(&mut |io_params| {
                        addr = io_params.address;
                        // We are always handling out IO port, so no data to return.
                        None
                    })
                    .expect("should handle IO successfully");
                    let regs = vcpu
                        .get_regs()
                        .expect("should retrieve the registers successfully");
                    match addr {
                        0x10 => {
                            assert_eq!(regs.rflags & FLAGS_IF_BIT, 0);
                            assert!(!vcpu.ready_for_interrupt());
                        }
                        0x20 => {
                            assert_eq!(regs.rflags & FLAGS_IF_BIT, FLAGS_IF_BIT);
                            assert!(vcpu.ready_for_interrupt());
                        }
                        _ => panic!("unexpected addr: {}", addr),
                    }
                    false
                }
                VcpuExit::Hlt => true,
                r => panic!("unexpected VMEXIT reason: {:?}", r),
            }
        }
    );
}

#[test]
fn test_enter_long_mode_direct() {
    global_asm_data!(
        pub long_mode_asm,
        ".code64",
        "mov rdx, rax",
        "mov rbx, [0x10000]",
        "hlt"
    );

    let bigly_mem_value: u64 = 0x1_0000_0000;
    let biglier_mem_value: u64 = 0x1_0000_0001;
    let mut setup = TestSetup {
        assembly: long_mode_asm::data().to_vec(),
        mem_size: 0x11000,
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rax: bigly_mem_value,
            rip: 0x1000,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),

        ..Default::default()
    };

    setup.add_memory_initialization(
        GuestAddress(0x10000),
        biglier_mem_value.to_le_bytes().to_vec(),
    );
    let regs_matcher = move |_: HypervisorType, regs: &Regs, sregs: &Sregs| {
        assert!((sregs.efer & 0x400) != 0, "Long-Mode Active bit not set");
        assert_eq!(
            regs.rdx, bigly_mem_value,
            "Did not execute instructions correctly in long mode."
        );
        assert_eq!(
            regs.rbx, biglier_mem_value,
            "Was not able to access translated memory in long mode."
        );
        assert_eq!((sregs.cs.l), 1, "Long-mode bit not set in CS");
    };

    let exit_matcher = |_, exit: &VcpuExit, _: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

// KVM fails on the wrmsr instruction with a shutdown vmexit; issues with
// running the asm in real-mode?
#[cfg(any(feature = "whpx", feature = "haxm"))]
#[test]
fn test_enter_long_mode_asm() {
    global_asm_data!(
        pub enter_long_mode_asm,
        ".code16",
        "lidt [0xd100]",             // IDT_OFFSET
        "mov eax, cr4",
        "or ax, 1 << 7 | 1 << 5",    // Set the PAE-bit (bit 5) and  PGE (bit 7).
        "mov cr4, eax",

        "mov bx, 0x9000",            // Address of the page table.
        "mov cr3, ebx",

        "mov ecx, 0xC0000080",       // Set ECX to EFER MSR (0xC0000080)
        "rdmsr",                     // Read from the MSR
        "or ax, 1 << 8",             // Set the LM-bit (bit 8).
        "wrmsr",                     // Write to the MSR

        "mov eax, cr0",
        "or eax, 1 << 31 | 1 << 0",  // Set PG (31nd bit) & PM (0th bit).
        "mov cr0, eax",

        "lgdt [0xd000]",             // Address of the GDT limit + base
        "ljmp 16, 0xe000"            // Address of long_mode_asm
    );

    global_asm_data!(
        pub long_mode_asm,
        ".code64",
        "mov rdx, r8",
        "mov rbx, [0x10000]",
        "hlt"
    );

    let bigly_mem_value: u64 = 0x1_0000_0000;
    let biglier_mem_value: u64 = 0x1_0000_0001;
    let mut setup = TestSetup {
        assembly: enter_long_mode_asm::data().to_vec(),
        mem_size: 0x13000,
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            r8: bigly_mem_value,
            rip: 0x1000,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|_: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            configure_long_mode_memory(vm);
        })),

        ..Default::default()
    };

    setup.add_memory_initialization(
        GuestAddress(0x10000),
        biglier_mem_value.to_le_bytes().to_vec(),
    );
    setup.add_memory_initialization(GuestAddress(0xe000), long_mode_asm::data().to_vec());
    // GDT limit + base, to be loaded by the lgdt instruction.
    // Must be within 0xFFFF as it's executed in real-mode.
    setup.add_memory_initialization(GuestAddress(0xd000), 0xFFFF_u32.to_le_bytes().to_vec());
    setup.add_memory_initialization(
        GuestAddress(0xd000 + 2),
        (GDT_OFFSET as u32).to_le_bytes().to_vec(),
    );

    // IDT limit + base, to be loaded by the lidt instruction.
    // Must be within 0xFFFF as it's executed in real-mode.
    setup.add_memory_initialization(GuestAddress(0xd100), 0xFFFF_u32.to_le_bytes().to_vec());
    setup.add_memory_initialization(
        GuestAddress(0xd100 + 2),
        (IDT_OFFSET as u32).to_le_bytes().to_vec(),
    );

    let regs_matcher = move |_: HypervisorType, regs: &Regs, sregs: &Sregs| {
        assert!((sregs.efer & 0x400) != 0, "Long-Mode Active bit not set");
        assert_eq!(
            regs.rdx, bigly_mem_value,
            "Did not execute instructions correctly in long mode."
        );
        assert_eq!(
            regs.rbx, biglier_mem_value,
            "Was not able to access translated memory in long mode."
        );
        assert_eq!((sregs.cs.l), 1, "Long-mode bit not set in CS");
    };

    let exit_matcher = |_, exit: &VcpuExit, _: &mut dyn VcpuX86_64| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_request_interrupt_window() {
    global_asm_data!(
        assembly,
        ".code16",
        // Disable the interrupt, and the interrupt window shouldn't cause a vcpu exit until the
        // interrupt is enabled again.
        "cli",
        // vcpu exit here to request an interrupt window when interrupt is not ready. We can't use
        // hlt for VMEXIT, because HAXM unconditionally allows interrupt injection for hlt.
        "out 0x10, ax",
        // Enable the interrupt.
        "sti",
        // Another instruction window for interrupt delivery after sti. We shouldn't receive the
        // interrupt window exit until we complete this instruction. We use another intercepted
        // instruction here to make sure the hypervisor doesn't shadow the not delivered interrupt
        // request window on an intercepted instruction.
        "out 0x10, ax",
        // WHPX requires another not intercepted instruction to restore from the not interruptible
        // state.
        "nop",
        // The interrupt window exit should happen either right before nop or right after nop.
        "hlt",
    );

    let assembly = assembly::data().to_vec();
    let setup = TestSetup {
        assembly: assembly.clone(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        intercept_intr: true,
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| assert_eq!(regs.rip, 0x1000 + assembly.len() as u64),
        {
            let mut io_counter = 0;
            let mut irq_window_received = false;
            move |hypervisor_type, exit, vcpu: &mut dyn VcpuX86_64| {
                let is_irq_window = if hypervisor_type == HypervisorType::Haxm {
                    matches!(exit, VcpuExit::Intr) && io_counter == 2
                } else {
                    matches!(exit, VcpuExit::IrqWindowOpen)
                };
                if is_irq_window {
                    assert_eq!(io_counter, 2);
                    assert!(vcpu.ready_for_interrupt());
                    vcpu.set_interrupt_window_requested(false);

                    irq_window_received = true;
                    return false;
                }
                match exit {
                    VcpuExit::Intr => false,
                    VcpuExit::Io => {
                        // We are always handling out IO port, so no data to return.
                        vcpu.handle_io(&mut |_| None)
                            .expect("should handle IO successfully");

                        assert!(!vcpu.ready_for_interrupt());

                        // Only set the interrupt window request on the first out instruction.
                        if io_counter == 0 {
                            vcpu.set_interrupt_window_requested(true);
                        }
                        io_counter += 1;
                        false
                    }
                    VcpuExit::Hlt => {
                        assert!(irq_window_received);
                        true
                    }
                    r => panic!("unexpected VMEXIT: {:?}", r),
                }
            }
        }
    );
}

#[cfg(any(feature = "whpx", feature = "haxm"))]
#[test]
fn test_fsgsbase() {
    global_asm_data!(
        pub fsgsbase_asm,
        ".code64",
        "wrfsbase rax",
        "wrgsbase rbx",
        "rdfsbase rcx",
        "rdgsbase rdx",
        "mov rax, fs:0",
        "mov rbx, gs:0",
        "hlt"
    );

    let code_addr = 0x1000;
    let fs = 0x10000;
    let gs = 0x10100;

    let setup = TestSetup {
        assembly: fsgsbase_asm::data().to_vec(),
        mem_size: 0x11000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rax: fs,
            rbx: gs,
            rip: code_addr,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);

            let mut sregs = vcpu.get_sregs().expect("unable to get sregs");
            sregs.cr4 |= 1 << 16; // FSGSBASE (bit 16)
            vcpu.set_sregs(&sregs).expect("unable to set sregs");
        })),
        memory_initializations: vec![
            (GuestAddress(fs), [0xaa; 8].into()),
            (GuestAddress(gs), [0xbb; 8].into()),
        ],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, sregs: &Sregs| {
        assert_eq!(regs.rcx, fs);
        assert_eq!(regs.rdx, gs);
        assert_eq!(regs.rax, 0xaaaaaaaaaaaaaaaa);
        assert_eq!(regs.rbx, 0xbbbbbbbbbbbbbbbb);
        assert_eq!(sregs.fs.base, fs);
        assert_eq!(sregs.gs.base, gs);
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
fn test_interrupt_injection_when_not_ready() {
    // This test ensures that if we inject an interrupt when it's not ready for interrupt, we
    // shouldn't end up with crash or hang. And if the interrupt is delivered, it shouldn't be
    // delivered before we reenable the interrupt.
    mod assembly {
        use super::*;

        global_asm_data!(
            pub init,
            ".code16",
            // Set the IDT
            "lidt [0x200]",
            // Set up the stack, which will be used when CPU transfers the control to the ISR on
            // interrupt.
            "mov sp, 0x900",
            // Set ax to 0.
            "xor ax, ax",
            // Set the address 0x910 to 1 when we disable the interrupt, and restore it to 0 after
            // we renable the interrupt.
            "mov word ptr [0x910], 1",
            "cli",
            // We can't use hlt for VMEXIT, because HAXM unconditionally allows interrupt injection
            // for hlt. We will inject an interrupt here although all hypervisors should report not
            // ready for injection an interrupt. And we don't care if the injection succeeds or not.
            "out 0x10, ax",
            "sti",
            // Set the address 0x910 to 0 when we renable the interrupt.
            "mov word ptr [0x910], 0",
            // For hypervisor that injects the interrupt later when it's ready, the interrupt will
            // be delivered here.
            "nop",
            "hlt",
        );

        // We still need an ISR in case the hypervisor actually delivers an interrupt.
        global_asm_data!(
            pub isr,
            ".code16",
            // ax will be 0 if the interrupt is delivered after we reenable the interrupt.
            // Otherwise, ax will be 1, and the test fails.
            "mov ax, word ptr [0x910]",
            "iret",
        );
    }

    let start_addr: u32 = 0x200;
    // Allocate exceed 0x900, where we set up our stack.
    let mem_size: u32 = 0x1000;

    let mut setup = TestSetup {
        load_addr: GuestAddress(start_addr.into()),
        initial_regs: Regs {
            rax: 0,
            // Set RFLAGS.IF to enable interrupt at the beginning.
            rflags: 2 | FLAGS_IF_BIT,
            ..Default::default()
        },
        mem_size: mem_size.into(),
        ..Default::default()
    };

    let mut cur_addr = start_addr;

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

    let isr_assembly = assembly::isr::data().to_vec();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), isr_assembly.clone());
    cur_addr += u32::try_from(isr_assembly.len()).expect("ISR size should be within u32");

    let init_assembly = assembly::init::data().to_vec();
    setup.initial_regs.rip = cur_addr.into();
    setup.add_memory_initialization(GuestAddress(cur_addr.into()), init_assembly.clone());
    cur_addr += u32::try_from(init_assembly.len()).expect("init size should be within u32");

    assert!(mem_size > cur_addr);

    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(
                regs.rax, 0,
                "the interrupt should be either not delivered(ax is kept as the initial value 0) \
                 or is delivered after we reenable the interrupt(when the ax is set from 0x910, \
                 0x910 is 0)"
            );
        },
        |_, exit, vcpu: &mut dyn VcpuX86_64| {
            match exit {
                // We exit and pass the test either the VCPU run fails or we hit hlt.
                VcpuExit::FailEntry { .. } | VcpuExit::Shutdown(..) | VcpuExit::Hlt => true,
                VcpuExit::Io => {
                    // We are always handling out IO port, so no data to return.
                    vcpu.handle_io(&mut |_| None)
                        .expect("should handle IO successfully");
                    assert!(!vcpu.ready_for_interrupt());
                    // We don't care whether we inject the interrupt successfully or not.
                    let _ = vcpu.interrupt(32);
                    false
                }
                r => panic!("unexpected VMEXIT reason: {:?}", r),
            }
        }
    );
}

#[test]
fn test_ready_for_interrupt_for_intercepted_instructions() {
    global_asm_data!(
        assembly,
        // We will use out instruction to cause VMEXITs and test ready_for_interrupt then.
        ".code16",
        // Disable the interrupt.
        "cli",
        // ready_for_interrupt should be false here.
        "out 0x10, ax",
        "sti",
        // ready_for_interrupt should be false here, because of the one instruction
        // interruptibility window for sti. And this is also an intercepted instruction.
        "out 0x20, ax",
        // ready_for_interrupt should be true here except for WHPX.
        "out 0x30, ax",
        // Restore the interruptibility for WHPX.
        "nop",
        "mov ax, ss",
        "mov ss, ax",
        // ready_for_interrupt should be false here, because of the one instruction
        // interruptibility window for mov ss. And this is also an intercepted instruction.
        "out 0x40, ax",
        // ready_for_interrupt should be true here except for WHPX.
        "out 0x50, ax",
        "hlt"
    );

    let assembly = assembly::data().to_vec();
    let setup = TestSetup {
        assembly: assembly.clone(),
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            // For VMEXIT caused by HLT, the hypervisor will automatically advance the rIP register.
            assert_eq!(regs.rip, 0x1000 + assembly.len() as u64);
        },
        |hypervisor_type, exit, vcpu| {
            match exit {
                VcpuExit::Hlt => true,
                VcpuExit::Io => {
                    let ready_for_interrupt = vcpu.ready_for_interrupt();
                    let mut io_port = 0;
                    vcpu.handle_io(&mut |params| {
                        io_port = params.address;
                        // We are always handling out IO port, so no data to return.
                        None
                    })
                    .expect("should handle port IO successfully");
                    match io_port {
                        0x10 | 0x20 | 0x40 => assert!(!ready_for_interrupt),
                        0x30 | 0x50 => {
                            // WHPX needs a not intercepted instruction to recover to the proper
                            // interruptibility state.
                            if hypervisor_type != HypervisorType::Whpx {
                                assert!(ready_for_interrupt);
                            }
                        }
                        _ => panic!("unexpected port {}", io_port),
                    }
                    false
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    );
}
