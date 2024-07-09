// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]
#![cfg(any(feature = "whpx", feature = "gvm", feature = "haxm", unix))]

use core::mem;
use std::arch::asm;
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base::set_cpu_affinity;
use base::MappedRegion;
use base::MemoryMappingBuilder;
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
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
#[cfg(windows)]
use windows::Win32::System::Memory::VirtualLock;
#[cfg(windows)]
use windows::Win32::System::Memory::VirtualUnlock;
use zerocopy::AsBytes;

const FLAGS_IF_BIT: u64 = 0x200;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum HypervisorType {
    Kvm,
    Whpx,
    Haxm,
    Gvm,
}

#[repr(C, packed)]
#[derive(AsBytes)]
/// Define IDTR value
struct Idtr {
    // The lower 2 bytes are limit.
    limit: u16,
    // The higher 4 bytes are base address.
    base_address: u32,
}

#[repr(C, packed)]
#[derive(AsBytes, Debug, Copy, Clone)]
struct IdtEntry {
    address_low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    address_mid: u16,
    address_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub fn new(handler_addr: u64) -> Self {
        IdtEntry {
            address_low: (handler_addr & 0xFFFF) as u16,
            selector: 0x10, // Our long mode CS is the third entry (0x0, 0x8, 0x10).
            ist: 0,
            flags: 0x8E, // Present, interrupt gate, DPL 0
            address_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
            address_high: (handler_addr >> 32) as u32,
            reserved: 0,
        }
    }
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
    mut exit_matcher: impl FnMut(HypervisorType, &VcpuExit, &mut dyn VcpuX86_64, &mut dyn Vm) -> bool,
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

    if !vm.check_capability(VmCap::EarlyInitCpuid) {
        let cpuid = vm
            .get_hypervisor()
            .get_supported_cpuid()
            .expect("get_supported_cpuid() failed");
        vcpu.set_cpuid(&cpuid).expect("set_cpuid() failed");
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
                    if exit_matcher(hypervisor_type, &other_exit, &mut *vcpu, &mut vm) {
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

// Condensed version of the function in x86_64\src\gdt.rs
pub fn segment_from_gdt(entry: u64, table_index: u8) -> Segment {
    let g = ((entry & 0x0080000000000000) >> 55) as u8;
    let limit = ((((entry) & 0x000F000000000000) >> 32) | ((entry) & 0x000000000000FFFF)) as u32;
    let limit_bytes = if g == 0 { limit } else { (limit * 4096) + 4095 };
    Segment {
        base: (((entry) & 0xFF00000000000000) >> 32)
            | (((entry) & 0x000000FF00000000) >> 16)
            | (((entry) & 0x00000000FFFF0000) >> 16),
        limit_bytes,
        selector: (table_index * 8) as u16,
        type_: ((entry & 0x00000F0000000000) >> 40) as u8,
        present: ((entry & 0x0000800000000000) >> 47) as u8,
        dpl: ((entry & 0x0000600000000000) >> 45) as u8,
        db: ((entry & 0x0040000000000000) >> 54) as u8,
        s: ((entry & 0x0000100000000000) >> 44) as u8,
        l: ((entry & 0x0020000000000000) >> 53) as u8,
        g,
        avl: ((entry & 0x0010000000000000) >> 52) as u8,
    }
}

pub fn null_descriptor() -> [u8; 8] {
    [0u8; 8]
}

const DESC_ACCESS_PRESENT: u8 = 1 << 7;
const DESC_ACCESS_NOT_SYS: u8 = 1 << 4;
const DESC_ACCESS_EXEC: u8 = 1 << 3;
const DESC_ACCESS_RW: u8 = 1 << 1;
const DESC_ACCESS_ACCESSED: u8 = 1 << 0;

const DESC_FLAG_GRAN_4K: u8 = 1 << 7;
const DESC_FLAG_DEFAULT_OP_SIZE_32: u8 = 1 << 6;
const DESC_FLAG_LONG_MODE: u8 = 1 << 5;

pub fn segment_descriptor(base: u32, limit: u32, access: u8, flags: u8) -> [u8; 8] {
    assert!(limit < (1 << 20)); // limit value must fit in 20 bits
    assert!(flags & 0x0F == 0x00); // flags must be in the high 4 bits only

    [
        limit as u8,                 // limit [7:0]
        (limit >> 8) as u8,          // limit [15:8]
        base as u8,                  // base [7:0]
        (base >> 8) as u8,           // base [15:8]
        (base >> 16) as u8,          // base [23:16]
        access,                      // type + s + dpl + p
        (limit >> 16) as u8 | flags, // limit [19:16] + flags
        (base >> 24) as u8,          // base [31:24]
    ]
}

pub fn write_gdt(guest_mem: &GuestMemory, gdt: &[u8]) {
    let gdt_addr = GuestAddress(GDT_OFFSET);
    guest_mem
        .write_at_addr(gdt, gdt_addr)
        .expect("Failed to write GDT entry to guest memory");
}

pub fn configure_long_mode_memory(vm: &mut dyn Vm) -> Segment {
    let guest_mem = vm.get_memory();

    assert!(
        guest_mem.range_overlap(GuestAddress(0x1500), GuestAddress(0xc000)),
        "Long-mode setup requires 0x1500-0xc000 to be mapped in the guest."
    );

    // Setup GDT
    let mut gdt = Vec::new();
    // 0x00
    gdt.extend_from_slice(&null_descriptor());
    // 0x08
    gdt.extend_from_slice(&null_descriptor());
    // 0x10: code segment descriptor
    gdt.extend_from_slice(&segment_descriptor(
        0x0,
        0xFFFFF,
        DESC_ACCESS_PRESENT
            | DESC_ACCESS_NOT_SYS
            | DESC_ACCESS_EXEC
            | DESC_ACCESS_RW
            | DESC_ACCESS_ACCESSED,
        DESC_FLAG_GRAN_4K | DESC_FLAG_LONG_MODE,
    ));

    write_gdt(guest_mem, &gdt);

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
    // The IDT limit should be 16 bytes * 256 entries - 1.
    sregs.idt.limit = 0xFFF;

    sregs.cs = code_seg;

    // Long mode
    sregs.cr0 |= 0x1 | 0x80000000; // PE & PG
    sregs.efer |= 0x100 | 0x400; // LME & LMA (Must be auto-enabled with CR0_PG)
    sregs.cr3 = pml4_addr.offset();
    sregs.cr4 |= 0x80 | 0x20; // PGE & PAE

    vcpu.set_sregs(&sregs).expect("failed to set sregs");
}

pub fn configure_flat_protected_mode_memory(vm: &mut dyn Vm) -> Segment {
    let guest_mem = vm.get_memory();

    assert!(
        guest_mem.range_overlap(GuestAddress(0x1500), GuestAddress(0xc000)),
        "Protected-mode setup requires 0x1500-0xc000 to be mapped in the guest."
    );

    // Setup GDT
    let mut gdt = Vec::new();

    // 0x00
    gdt.extend_from_slice(&null_descriptor());
    // 0x08
    gdt.extend_from_slice(&null_descriptor());
    // 0x10: code segment descriptor
    gdt.extend_from_slice(&segment_descriptor(
        0x0,
        0xFFFFF,
        DESC_ACCESS_PRESENT
            | DESC_ACCESS_NOT_SYS
            | DESC_ACCESS_EXEC
            | DESC_ACCESS_RW
            | DESC_ACCESS_ACCESSED,
        DESC_FLAG_GRAN_4K | DESC_FLAG_DEFAULT_OP_SIZE_32,
    ));

    write_gdt(guest_mem, &gdt);

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

    code_seg
}

pub fn enter_protected_mode(vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm) {
    let code_seg = configure_flat_protected_mode_memory(vm);

    let mut sregs = vcpu.get_sregs().expect("failed to get sregs");

    sregs.cs = code_seg;

    sregs.gdt.base = GDT_OFFSET;
    sregs.gdt.limit = 0xFFFF;

    sregs.idt.base = IDT_OFFSET;
    sregs.idt.limit = 0xFFF;

    // 32-bit protected mode, paging disabled
    sregs.cr0 |= 0x1; // PE
    sregs.cr0 &= !0x80000000; // ~PG

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
        |_, exit: &_, _: &mut _, _: &mut _| -> bool { matches!(exit, VcpuExit::Hlt) }
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
    let exit_matcher =
        move |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
                                Ok(Some([0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0]))
                            }
                            // Second MMIO read is a regular read from an
                            // unmapped memory (pointed to by initial EAX).
                            (0x3010, 1) => Ok(Some([0x66, 0, 0, 0, 0, 0, 0, 0])),
                            _ => {
                                panic!("invalid address({:#x})/size({})", address, size)
                            }
                        }
                    }
                    IoOperation::Write { data } => {
                        assert_eq!(address, 0x3000);
                        assert_eq!(data[0], 0x33);
                        assert_eq!(size, 1);
                        Ok(None)
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

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
                    Ok(None)
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
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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
            }
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
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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

    let exit_matcher =
        move |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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

    let exit_matcher = |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
        |_, _, _, _: &mut dyn Vm| {
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

    let exit_matcher = |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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
        move |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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

    let exit_matcher =
        move |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
            |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
                match hypervisor_type {
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
        |hypervisor_type, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
            match hypervisor_type {
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

    let exit_matcher = |_: HypervisorType,
                        exit: &VcpuExit,
                        _: &mut dyn VcpuX86_64,
                        _: &mut dyn Vm| { matches!(exit, VcpuExit::Hlt) };

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
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
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
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
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
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
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
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
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
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
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
        |_, exit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
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
        |_, exit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
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
        |_, exit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
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
        |_, exit, vcpu, _: &mut dyn Vm| {
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

    let exit_matcher = |_, exit: &VcpuExit, _: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

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

    let exit_matcher = |_, exit: &VcpuExit, _: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
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
            move |hypervisor_type, exit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
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

    let exit_matcher = |_, exit: &VcpuExit, _vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests whether MMX state is being preserved by the hypervisor correctly (e.g. the hypervisor is
/// properly using fxsave/fxrstor, or xsave/xrstor (or xsaves/xrstors)).
#[test]
fn test_mmx_state_is_preserved_by_hypervisor() {
    // This program stores a sentinel value into mm0 (the first MMX register) and verifies
    // that after a vmexit, that value is properly restored (we copy it to rbx so it can be checked
    // by the reg matcher when the VM hlts). In the vmexit handler function below, we make sure the
    // sentinel value is NOT in mm0. This way we know the mm0 value has changed, so we're guaranteed
    // the hypervisor has to restore the guest's sentinel value for the test to pass. (The read
    // from mm0 to rbx happens *after* the vmexit, so the hypervisor has to restore the guest's
    // mm0 otherwise there will be random garbage in there from the host. This would also be a
    // security issue.)
    //
    // Note: this program also verifies the guest has MMX support. If it does not, rdx will be 1 and
    // no MMX instructions will be attempted.
    let sentinel_mm0_value = 0x1337FFFFu64;
    global_asm_data!(
        pub mmx_ops_asm,
        ".code64",
        "mov eax, 1",
        "cpuid",
        "bt edx, 23",
        "jc HasMMX",
        "mov rdx, 1",
        "hlt",
        "HasMMX:",
        "xor rdx, rdx",
        "mov rax, 0x1337FFFF",
        "mov rbx, 0x0",
        "movq mm0, rax",
        "out 0x5, al",
        "movq rbx, mm0",
        "emms",
        "hlt",
    );

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: mmx_ops_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        memory_initializations: vec![],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_ne!(regs.rdx, 1, "guest has no MMX support");
        assert_eq!(
            regs.rbx, sentinel_mm0_value,
            "guest MMX register not restored by hypervisor"
        );
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        VcpuExit::Cpuid { entry } => {
            vcpu.handle_cpuid(entry)
                .expect("should handle cpuid successfully");
            false
        }
        VcpuExit::Io => {
            vcpu.handle_io(&mut |_| None)
                .expect("should handle IO successfully");

            // kaiyili@ pointed out we should check the XSAVE state exposed by the hypervisor via
            // its API (e.g. vm.get_xsave_state). This is used in snapshotting, so if it's wrong,
            // that would break things. It's also a good cross-check that the hypervisor is properly
            // handling xsave state.
            //
            // There are a couple of things blocking us from doing that today:
            //      1. gHAXM, our hypervisor of interest, doesn't expose its xsave area state for
            //         the guest.
            //      2. We don't have an xsave area parser (yet).

            // mm0 MUST NOT have the guest's sentinel value. If it somehow does, the hypervisor
            // didn't save the guest's FPU/MMX state / restore the host's state before exiting to
            // CrosVM.
            //
            // Note: MMX is ubiquitous on x86_64, so we don't check for support on the host (the
            // guest checks, so unless the guest's support is software implemented, it's highly
            // likely the host has MMX support).
            let mut mm0_value: u64;
            // SAFETY: we do not clobber any undeclared registers. Technically emms changes some
            // x87 state, so there's some UB risk here, but it is not explicitly called out by
            // the Rust docs as a bad idea.
            unsafe {
                asm!(
                    "movq rax, mm0",
                    "emms",
                    out("rax") mm0_value);
            }
            assert_ne!(
                mm0_value, sentinel_mm0_value,
                "host mm0 value is the same as the guest sentinel value"
            );
            false
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests whether AVX state is being preserved by the hypervisor correctly (e.g. the hypervisor is
/// properly using xsave/xrstor (or xsaves/xrstors)). This is very similar to the MMX test, but
/// AVX state is *not* captured by fxsave, so that's how we guarantee xsave state of some kind is
/// being handled properly.
#[test]
fn test_avx_state_is_preserved_by_hypervisor() {
    if !is_x86_feature_detected!("avx") {
        panic!("this test requires host AVX support and it was not detected");
    }

    let sentinel_value = 0x1337FFFFu64;
    global_asm_data!(
        pub avx_ops_asm,
        ".code64",
        "mov eax, 1",
        "cpuid",
        "bt ecx, 28",
        "jc HasAVX",
        "mov rdx, 1",
        "hlt",
        "HasAVX:",

        // Turn on OSXSAVE (we can't touch XCR0 without it).
        "mov rax, cr4",
        "or eax, 1 << 18",
        "mov cr4, rax",

        // AVX won't work unless we enable it.
        //
        // Set the relevant XCR0 bits:
        //   0: X87
        //   1: SSE
        //   2: AVX
        "xor rcx, rcx",
        "xgetbv",
        // (7 = 111b)
        "or eax, 7",
        "xsetbv",

        // Now that AVX is ready to use, let's start with a clean slate (and signify we have AVX
        // support to the test assert below by zeroing rdx).
        "xor rdx, rdx",
        "xor rax, rax",
        "xor rbx, rbx",
        "vzeroall",

        // Here's the actual test (finally). Since AVX is a little tricky to follow, here's what
        // the test does:
        //      1. We load 0x1337FFFF into ymm1 via xmm0.
        //      2. We perform port IO to exit out to CrosVM (our vmexit handler below).
        //      3. The vmexit handler makes sure ymm1 does NOT contain 0x1337FFFF.
        //      4. We return to this program. Then we dump the value of ymm1 into ebx. The exit
        //         register matcher verifies that 0x1337FFFF is in ebx. This means the hypervisor
        //         properly restored ymm1 for the guest on vmenter.
        "mov eax, 0x1337FFFF",
        "vpinsrd xmm0, xmm1, eax, 3",
        "vinserti128 ymm1, ymm2, xmm0, 1",
        "out 0x5, al",
        "vextracti128 xmm3, ymm1, 1",
        "vpextrd ebx, xmm3, 3",
        "hlt",
    );

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: avx_ops_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        memory_initializations: vec![],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_ne!(regs.rdx, 1, "guest has no AVX support");
        assert_eq!(
            regs.rbx, sentinel_value,
            "guest AVX register not restored by hypervisor"
        );
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        VcpuExit::Cpuid { entry } => {
            vcpu.handle_cpuid(entry)
                .expect("should handle cpuid successfully");
            false
        }
        VcpuExit::Io => {
            vcpu.handle_io(&mut |_| None)
                .expect("should handle IO successfully");

            // kaiyili@ pointed out we should check the XSAVE state exposed by the hypervisor via
            // its API (e.g. vm.get_xsave_state). This is used in snapshotting, so if it's wrong,
            // that would break things. It's also a good cross-check that the hypervisor is properly
            // handling xsave state.
            //
            // There are a couple of things blocking us from doing that today:
            //      1. gHAXM, our hypervisor of interest, doesn't expose its xsave area state for
            //         the guest.
            //      2. We don't have a xsave area parser (yet).

            // ymm1 MUST NOT have the guest's sentinel value. If it somehow does, the hypervisor
            // didn't save the guest's AVX state / restore the host's state before exiting to
            // CrosVM.
            //
            // Note: AVX is ubiquitous on x86_64, so we don't check for support on the host (the
            // guest checks, so unless the guest's support is software implemented, it's highly
            // likely the host has AVX support).
            let mut ymm1_sub_value: u64;
            // SAFETY: we don't clobber any undeclared registers.
            unsafe {
                asm!(
                "vextracti128 xmm4, ymm1, 1",
                "vpextrd eax, xmm4, 3",
                out("rax") ymm1_sub_value,
                out("xmm4") _);
            }
            assert_ne!(
                ymm1_sub_value, sentinel_value,
                "host ymm1 value is the same as the guest sentinel value. Hypervisor likely didn't \
                    save guest's state."
            );
            false
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests whether XSAVE works inside a guest.
#[test]
fn test_xsave() {
    let sentinel_xmm0_value = 0x1337FFFFu64;
    global_asm_data!(
        pub xsave_ops_asm,
        ".code64",

        // Make sure XSAVE is supported.
        "mov eax, 1",
        "mov ecx, 0",
        "cpuid",
        "bt ecx, 26",
        "jc HasXSAVE",
        "mov rdx, 1",
        "hlt",
        "HasXSAVE:",
        "xor rdx, rdx",

        // Turn on OSXSAVE.
        "mov rax, cr4",
        "or eax, 1 << 18",
        "mov cr4, rax",

        // Enable X87, SSE, and AVX.
        //
        // Set the relevant XCR0 bits:
        //   0: X87
        //   1: SSE
        //   3: AVX
        "xor rcx, rcx",
        "xgetbv",
        // (7 = 111b)
        "or eax, 7",
        "xsetbv",

        // Put the sentinel value in xmm0, and save it off.
        "mov eax, 0x1337FFFF",
        "vzeroall",
        "vpinsrd xmm0, xmm1, eax, 3",
        "xor edx, edx",
        "mov eax, 7",
        "xsave dword ptr [0x10000]",

        // Clear xmm0.
        "vpxor xmm0, xmm0, xmm0",

        // Restoring should put the sentinel value back.
        "xor edx, edx",
        "mov eax, 7",
        "xrstor dword ptr [0x10000]",

        "xor rbx, rbx",
        "vpextrd ebx, xmm0, 3",
        "hlt",
    );

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: xsave_ops_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        memory_initializations: vec![(GuestAddress(0x10000), vec![0; 0x1000])],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_ne!(regs.rdx, 1, "guest has no XSAVE support");
        assert_eq!(
            regs.rbx, sentinel_xmm0_value,
            "guest SSE register not restored by XRSTOR",
        );
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        VcpuExit::Cpuid { entry } => {
            vcpu.handle_cpuid(entry)
                .expect("should handle cpuid successfully");
            false
        }
        VcpuExit::MsrAccess => false, // MsrAccess handled by hypervisor impl
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests whether XSAVES works inside a guest.
///
/// Ignored because CET is not available in some nested virtualization
/// environments (such as CI). (CET is the feature we use to test XSAVES.)
#[ignore]
#[cfg(feature = "whpx")]
#[test]
fn test_xsaves() {
    global_asm_data!(
        pub xsaves_ops_asm,
        ".code64",

        // Make sure XSAVES is supported.
        "mov eax, 0xd",
        "mov ecx, 1",
        "cpuid",
        "bt eax, 3",
        "jc HasXSAVES",
        "mov rdx, 1",
        "hlt",
        "HasXSAVES:",

        // Make sure CET is supported.
        "mov eax, 7",
        "mov ecx, 0",
        "cpuid",
        "bt ecx, 7",
        "jc HasCET",
        "mov rdx, 2",
        "hlt",
        "HasCET:",

        // Turn on write protection for ring 0 (required by CET).
        "mov rax, cr0",
        "or eax, 1 << 16",
        "mov cr0, rax",

        // Turn on OSXSAVE (18) and CET (23).
        "mov rax, cr4",
        "or eax, 1 << 18",
        "or eax, 1 << 23",
        "mov cr4, rax",

        // Set up XSAVES to manage CET state.
        // IA32_XSS = 0x0DA0
        "mov ecx, 0x0DA0",
        "rdmsr",
        "or eax, 1 << 12",
        "wrmsr",

        // Enable CET.
        "mov ecx, 0x6A2",
        "rdmsr",
        "or eax, 1",
        "wrmsr",

        // Now CET is usable and managed by XSAVES. Let's set a sentinel value and make sure xsaves
        // restores it as expected. Note that PL0_SSP's linear address must be 8 byte aligned.
        // PL0_SSP = 0x06A5
        "mov ecx, 0x06A4",
        "xor edx, edx",
        "xor eax, eax",
        "mov eax, 0x13370000",
        "wrmsr",

        // Set the RFBM / feature mask to include CET.
        "xor edx, edx",
        "mov eax, 1 << 12",
        "xsaves dword ptr [0x10000]",

        // Clear PL0_SSP
        "xor edx, edx",
        "xor eax, eax",
        "mov ecx, 0x06A4",
        "wrmsr",

        // Set the RFBM / feature mask to include CET.
        "xor edx, edx",
        "mov eax, 1 << 12",
        "xrstors dword ptr [0x10000]",

        // Check to see if PL0_SSP was restored.
        "mov ecx, 0x06A4",
        "rdmsr",
        "cmp eax, 0x13370000",
        "jz TestPasses",
        "mov rdx, 3",
        "hlt",
        "TestPasses:",
        "xor rdx, rdx",
        "hlt",
    );

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: xsaves_ops_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rdx: 0x4,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        memory_initializations: vec![(GuestAddress(0x10000), vec![0; 0x1000])],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_ne!(regs.rdx, 1, "guest has no XSAVES support");
        assert_ne!(regs.rdx, 2, "guest has no CET support");
        assert_ne!(regs.rdx, 3, "guest didn't restore PL0_SSP as expected");
        assert_eq!(regs.rdx, 0, "test failed unexpectedly");
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        VcpuExit::Cpuid { entry } => {
            vcpu.handle_cpuid(entry)
                .expect("should handle cpuid successfully");
            false
        }
        VcpuExit::MsrAccess => false, // MsrAccess handled by hypervisor impl
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests that XSAVES is disabled in gHAXM (it's unsupported).
///
/// Note: this test passing in CI is not necessarily a signal that gHAXM is working correctly
/// because XSAVES is disabled in some nested virtualization environments (e.g. CI).
#[cfg(feature = "haxm")]
#[test]
fn test_xsaves_is_disabled_on_haxm() {
    global_asm_data!(
        pub no_xsaves_asm,
        ".code64",

        "mov eax, 0xd",
        "mov ecx, 1",
        "cpuid",
        "bt eax, 3",
        "jnc NoXSAVES",
        "mov rdx, 1",
        "hlt",
        "NoXSAVES:",
        "mov rdx, 0",
        "hlt",
    );

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: no_xsaves_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rdx: 0x2,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        memory_initializations: vec![],
        ..Default::default()
    };

    let regs_matcher = move |_: HypervisorType, regs: &Regs, _: &_| {
        assert_ne!(regs.rdx, 1, "guest has XSAVES support and shouldn't");
        assert_eq!(regs.rdx, 0, "test failed unexpectedly");
    };

    let exit_matcher = |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        VcpuExit::Cpuid { entry } => {
            vcpu.handle_cpuid(entry)
                .expect("should handle cpuid successfully");
            false
        }
        VcpuExit::MsrAccess => false, // MsrAccess handled by hypervisor impl
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

/// Tests whether SLAT is updated properly when a region is removed from the guest. A correctly
/// implemented hypervisor will flush the TLB such that this immediately hits a SLAT fault and comes
/// to us as MMIO. If we don't see that, and the guest actually reads from the removed region, the
/// test will fail. In the real world, this would be a guest read from a random pfn, which is
/// UB (and a major security problem).
///
/// Flakes should be treated as real failures (this test can show a false negative, but never a
/// false positive).
#[test]
fn test_slat_on_region_removal_is_mmio() {
    global_asm_data!(
        pub test_asm,
        ".code64",

        // Load the TLB with a mapping for the test region.
        "mov al, byte ptr [0x20000]",

        // Signal to the host that VM is running. On this vmexit, the host will unmap the test
        // region.
        "out 0x5, al",

        // This read should result in MMIO, and if it does, the test passes. If we hit the hlt, then
        // the test fails (since it means we were able to satisfy this read without exiting).
        "mov al, byte ptr [0x20000]",
        "hlt"
    );

    const TEST_MEM_REGION_SIZE: usize = 0x1000;
    let memslot: Arc<Mutex<Option<MemSlot>>> = Arc::new(Mutex::new(None));
    let memslot_for_func = memslot.clone();

    let code_addr = 0x1000;
    let setup = TestSetup {
        assembly: test_asm::data().to_vec(),
        mem_size: 0x12000,
        load_addr: GuestAddress(code_addr),
        initial_regs: Regs {
            rip: code_addr,
            rflags: 0x2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(
            move |vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
                enter_long_mode(vcpu, vm);

                // Create a test pinned memory region that is all 0xFF.
                let shm = SharedMemory::new("test", TEST_MEM_REGION_SIZE as u64).unwrap();
                let test_region = Box::new(
                    MemoryMappingBuilder::new(TEST_MEM_REGION_SIZE)
                        .from_shared_memory(&shm)
                        .build()
                        .unwrap(),
                );
                let ff_init = [0xFFu8; TEST_MEM_REGION_SIZE];
                test_region.write_slice(&ff_init, 0).unwrap();
                let test_region = Box::new(
                    PinnedMemoryRegion::new(test_region).expect("failed to pin test region"),
                );
                *memslot_for_func.lock() = Some(
                    vm.add_memory_region(
                        GuestAddress(0x20000),
                        test_region,
                        false,
                        false,
                        MemCacheType::CacheCoherent,
                    )
                    .unwrap(),
                );
            },
        )),
        memory_initializations: vec![],
        ..Default::default()
    };

    // Holds the test memory region after it's unmapped and the VM is still running. Without this,
    // incorrect access to the region by the VM would be unsafe / UB.
    let test_region_arc: Arc<Mutex<Option<Box<dyn MappedRegion>>>> = Arc::new(Mutex::new(None));
    let test_region_arc_for_exit = test_region_arc.clone();

    let exit_matcher =
        move |_, exit: &VcpuExit, vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| match exit {
            VcpuExit::Io => {
                // WHPX insists on data being returned here or it throws MemoryCallbackFailed.
                //
                // We strictly don't care what this data is, since the VM exits before running any
                // further instructions.
                vcpu.handle_io(&mut |_| None)
                    .expect("should handle IO successfully");

                // Remove the test memory region to cause a SLAT fault (in the passing case).
                //
                // This also ensures the memory region remains pinned in host physical memory so any
                // incorrect accesses to it by the VM will remain safe.
                *test_region_arc_for_exit.lock() =
                    Some(vm.remove_memory_region(memslot.lock().unwrap()).unwrap());
                false
            }
            VcpuExit::Mmio => {
                vcpu.handle_mmio(&mut |IoParams {
                                           address,
                                           size,
                                           operation,
                                       }| {
                    assert_eq!(address, 0x20000, "MMIO for wrong address");
                    assert_eq!(size, 1);
                    assert!(
                        matches!(operation, IoOperation::Read),
                        "got unexpected IO operation {:?}",
                        operation
                    );
                    // We won't vmenter again, so there's no need to actually satisfy the MMIO by
                    // returning data; however, some hypervisors (WHPX) require it.
                    Ok(Some([0u8; 8]))
                })
                .unwrap();
                true
            }
            VcpuExit::Hlt => {
                panic!("VM should not reach the hlt instruction (MMIO should've ended the VM)");
            }
            r => panic!("unexpected exit reason: {:?}", r),
        };

    // We want to catch if the hypervisor doesn't clear the VM's TLB. If we hop between CPUs, then
    // we're likely to end up with a clean TLB on another CPU.
    set_cpu_affinity(vec![0]).unwrap();

    run_tests!(setup, move |_, _, _| {}, &exit_matcher);
}

struct PinnedMemoryRegion {
    mem_region: Box<dyn MappedRegion>,
}

impl PinnedMemoryRegion {
    fn new(mem_region: Box<dyn MappedRegion>) -> base::Result<Self> {
        // SAFETY:
        // ptr is a valid pointer and points to a region of the supplied size.
        unsafe { pin_memory(mem_region.as_ptr() as *mut _, mem_region.size()) }?;
        Ok(Self { mem_region })
    }
}

// SAFETY:
// Safe because ptr & size a memory range owned by this MemoryMapping that won't be unmapped
// until it's dropped.
unsafe impl MappedRegion for PinnedMemoryRegion {
    fn as_ptr(&self) -> *mut u8 {
        self.mem_region.as_ptr()
    }

    fn size(&self) -> usize {
        self.mem_region.size()
    }
}

impl Drop for PinnedMemoryRegion {
    fn drop(&mut self) {
        // SAFETY:
        // memory region passed is a valid pointer and points to a region of the
        // supplied size. We also panic on failure.
        unsafe { unpin_memory(self.mem_region.as_ptr() as *mut _, self.mem_region.size()) }
            .expect("failed to unpin memory")
    }
}

unsafe fn pin_memory(ptr: *mut c_void, len: usize) -> base::Result<()> {
    #[cfg(windows)]
    {
        if VirtualLock(ptr, len).into() {
            Ok(())
        } else {
            Err(base::Error::last())
        }
    }
    #[cfg(unix)]
    {
        if libc::mlock(ptr, len) != 0 {
            Err(base::Error::last())
        } else {
            Ok(())
        }
    }
}

unsafe fn unpin_memory(ptr: *mut c_void, len: usize) -> base::Result<()> {
    #[cfg(windows)]
    {
        if VirtualUnlock(ptr, len).into() {
            Ok(())
        } else {
            Err(base::Error::last())
        }
    }
    #[cfg(unix)]
    {
        if libc::munlock(ptr, len) != 0 {
            Err(base::Error::last())
        } else {
            Ok(())
        }
    }
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
        |_, exit, vcpu: &mut dyn VcpuX86_64, _: &mut dyn Vm| {
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
        |hypervisor_type, exit, vcpu, _: &mut dyn Vm| {
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

#[test]
fn test_hardware_breakpoint_with_isr() {
    global_asm_data!(
        setup_debug_handler_code,
        ".code64",
        // Set up the stack
        "mov sp, 0x900",
        "mov rax, 0x1019", // Address of the instruction to trigger the breakpoint
        "mov dr0, rax",
        "mov rax, 0x00000001", // Enable the first breakpoint (local, exact) for execution
        "mov dr7, rax",
        "nop", // This should trigger the debug exception
        "nop",
        "hlt"
    );

    global_asm_data!(
        debug_isr_code,
        ".code64",
        "mov rbx, 0xf00dbabe", // Set a value to indicate the ISR was called
        "mov rax, 0",
        "mov dr7, rax", // Disable debugging again
        "mov rax, dr6",
        "iretq" // Return from interrupt
    );

    global_asm_data!(
        null_isr_code,
        ".code64",
        "mov rbx, 0xbaadf00d", // This ISR should never get called
        "hlt"
    );

    let debug_isr_offset = 0x800;
    let null_isr_offset = 0x700;
    let debug_idt_entry = IdtEntry::new(debug_isr_offset);
    let null_idt_entry = IdtEntry::new(null_isr_offset);

    let idt = (0..256)
        .flat_map(|i| {
            let entry = if i == 0x01 {
                debug_idt_entry
            } else {
                null_idt_entry
            };
            entry.as_bytes().to_owned()
        })
        .collect::<Vec<_>>();

    let idt_base = 0x12000;

    let setup = TestSetup {
        assembly: setup_debug_handler_code::data().to_vec(),
        load_addr: GuestAddress(0x1000),
        mem_size: 0x20000,
        initial_regs: Regs {
            rip: 0x1000,
            rflags: 2 | FLAGS_IF_BIT,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(
            move |vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
                enter_long_mode(vcpu, vm);

                let guest_mem = vm.get_memory();

                // Write IDT to guest memory
                guest_mem
                    .write_at_addr(idt.as_bytes(), GuestAddress(idt_base))
                    .expect("Failed to write IDT entry");

                guest_mem
                    .write_at_addr(
                        debug_isr_code::data().to_vec().as_bytes(),
                        GuestAddress(debug_isr_offset),
                    )
                    .expect("Failed to write debug ISR entry");

                guest_mem
                    .write_at_addr(
                        null_isr_code::data().to_vec().as_bytes(),
                        GuestAddress(null_isr_offset),
                    )
                    .expect("Failed to write null ISR entry");

                // Set the IDT
                let mut sregs = vcpu.get_sregs().expect("Failed to get sregs");
                sregs.idt.base = idt_base;
                sregs.idt.limit = (core::mem::size_of::<IdtEntry>() * 256 - 1) as u16;
                vcpu.set_sregs(&sregs).expect("Failed to set sregs");
            },
        )),
        ..Default::default()
    };

    let regs_matcher = |_: HypervisorType, regs: &Regs, _: &Sregs| {
        assert_eq!(regs.rax & 1, 1, "Breakpoint #0 not hit");
        assert_eq!(
            regs.rip,
            0x1000 + (setup_debug_handler_code::data().len() as u64),
            "rIP not at the right HLT"
        );
        assert_eq!(regs.rbx, 0xf00dbabe, "Debug ISR was not called");
    };

    let exit_matcher = |_, exit: &VcpuExit, _: &mut dyn VcpuX86_64, _: &mut dyn Vm| match exit {
        VcpuExit::Hlt => {
            true // Break VM runloop
        }
        r => panic!("unexpected exit reason: {:?}", r),
    };

    run_tests!(setup, regs_matcher, exit_matcher);
}

#[test]
fn test_debug_register_persistence() {
    global_asm_data!(
        test_debug_registers_code,
        ".code64",
        "mov dr0, rax",
        "inc rax",
        "mov dr1, rax",
        "inc rax",
        "mov dr2, rax",
        "inc rax",
        "mov dr3, rax",
        // Perform HLT to cause VMEXIT
        "hlt",
        "mov r8, dr0",
        "mov r9, dr1",
        "mov r10, dr2",
        "mov r11, dr3",
        "hlt"
    );

    let initial_dr_value: u64 = 0x12345678;

    let setup = TestSetup {
        assembly: test_debug_registers_code::data().to_vec(),
        mem_size: 0x11000,
        load_addr: GuestAddress(0x1000),
        initial_regs: Regs {
            rax: initial_dr_value,
            rip: 0x1000,
            rflags: 2,
            ..Default::default()
        },
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);
        })),
        ..Default::default()
    };

    let mut hlt_count = 0;

    run_tests!(
        setup,
        |_, regs, _| {
            assert_eq!(regs.r8, initial_dr_value, "DR0 value mismatch after VMEXIT");
            assert_eq!(
                regs.r9,
                initial_dr_value + 1,
                "DR1 value mismatch after VMEXIT"
            );
            assert_eq!(
                regs.r10,
                initial_dr_value + 2,
                "DR2 value mismatch after VMEXIT"
            );
            assert_eq!(
                regs.r11,
                initial_dr_value + 3,
                "DR3 value mismatch after VMEXIT"
            );
        },
        |_, exit, _, _: &mut dyn Vm| match exit {
            VcpuExit::Hlt => {
                hlt_count += 1;
                hlt_count > 1 // Halt execution after the second HLT
            }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    );
}

#[test]
fn test_minimal_exception_injection() {
    // This test tries to write an invalid MSR, causing a General Protection exception to be
    // injected by the hypervisor (since MSR writes cause a VMEXIT). We run it in long mode since
    // real mode exception handling isn't always well supported (failed on Intel HAXM).
    mod assembly {
        use super::*;

        // An ISR that handles any generic interrupt.
        global_asm_data!(
            pub isr_generic,
            ".code64",
            // Set EBX to 888 to observe this is where we halted.
            "mov ebx, 888",
            "hlt"
        );

        // An ISR that handles the General Protection fault specifically.
        global_asm_data!(
            pub isr_gp,
            ".code64",
            // Set EBX to 999 to observe this is where we halted.
            "mov ebx, 999",
            "hlt"
        );

        // Our VM entry (in long mode).
        global_asm_data!(
            pub init,
            ".code64",
            // Set up the stack, which will be used when CPU transfers the control to the ISR. If
            // not set up, can cause faults (stack should be aligned).
            "mov esp, 0x900",
            // We will verify EBX, set it here first.
            "mov ebx, 777",
            // Should trigger GP fault when we try to write to MSR 0.
            "wrmsr",
            // We should never get here since we halt in the fault handlers.
            "hlt",
        );
    }

    let mem_size: u64 = 0x20000;

    let setup = TestSetup {
        initial_regs: Regs {
            // WRMSR will try to write to ECX, we set it to zero to point to an old read-only MSR
            // (IA32_P5_MC_ADDR).
            rcx: 0,
            // Intentionally not setting IF flag since exceptions don't check it.
            rflags: 2,
            ..Default::default()
        },
        mem_size,
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_long_mode(vcpu, vm);

            let start_addr: u64 = 0x1000;
            let guest_mem = vm.get_memory();

            let isr_assembly = assembly::isr_generic::data().to_vec();
            let isr_assembly_len =
                u64::try_from(isr_assembly.len()).expect("ISR size should be within u64");

            let isr_gp_assembly = assembly::isr_gp::data().to_vec();
            let isr_gp_assembly_len =
                u64::try_from(isr_gp_assembly.len()).expect("GP ISR size should be within u64");

            let mut cur_addr = start_addr;

            guest_mem
                .write_at_addr(&isr_assembly, GuestAddress(cur_addr))
                .expect("Failed to write ISR to guest memory");
            cur_addr += isr_assembly_len;

            guest_mem
                .write_at_addr(&isr_gp_assembly, GuestAddress(cur_addr))
                .expect("Failed to write ISR to guest memory");
            cur_addr += isr_gp_assembly_len;

            let mut regs = vcpu.get_regs().expect("Failed to get regs");
            regs.rip = cur_addr;
            vcpu.set_regs(&regs).expect("Failed to set regs");

            let init_assembly = assembly::init::data().to_vec();
            guest_mem
                .write_at_addr(&init_assembly, GuestAddress(cur_addr))
                .expect("Failed to write init assembly to guest memory");

            let idt_entry_generic = IdtEntry::new(start_addr);
            let idt_entry_gp = IdtEntry::new(start_addr + isr_assembly_len);

            // Construct an IDT with an entry for each possible vector.
            let idt = (0..256)
                .flat_map(|i| {
                    // GP handler is vector 13.
                    let isr_address = if i == 0x0D {
                        idt_entry_gp
                    } else {
                        idt_entry_generic
                    };

                    isr_address.as_bytes().to_owned()
                })
                .collect::<Vec<_>>();

            // Write the IDT to memory.
            let idt_base = 0x12000;
            guest_mem
                .write_at_addr(&idt, GuestAddress(idt_base))
                .expect("Failed to write IDT to guest memory");

            // Set the IDT in our registers.
            let mut sregs = vcpu.get_sregs().expect("Failed to get sregs");
            sregs.idt.base = idt_base;
            sregs.idt.limit = (core::mem::size_of::<IdtEntry>() * 256 - 1) as u16;
            vcpu.set_sregs(&sregs).expect("Failed to set sregs");
        })),
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            // If EBX is 999 the GP handler ran.
            assert_eq!(regs.rbx, 999);
        },
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
    );
}

#[test]
fn test_pmode_segment_limit() {
    // This test configures 32-bit protected mode and verifies that segment limits are converted
    // correctly. The test setup configures a segment with the 20-bit limit field set to 0xFFFFF and
    // the 4096-byte granularity bit set, which should result in a 4 GB limit (0xFFFFFFFF).
    mod assembly {
        use super::*;

        global_asm_data!(
            pub init,
            ".code32",
            // Load the CS segment limit into EAX.
            "mov cx, cs",
            "lsl eax, cx",
            "hlt",
        );
    }

    let mem_size: u64 = 0x20000;

    let setup = TestSetup {
        initial_regs: Regs {
            ..Default::default()
        },
        mem_size,
        extra_vm_setup: Some(Box::new(|vcpu: &mut dyn VcpuX86_64, vm: &mut dyn Vm| {
            enter_protected_mode(vcpu, vm);

            let guest_mem = vm.get_memory();

            let mut regs = vcpu.get_regs().expect("Failed to get regs");
            regs.rax = 12345;
            regs.rip = 0x1000;
            vcpu.set_regs(&regs).expect("Failed to set regs");

            let init_assembly = assembly::init::data().to_vec();
            guest_mem
                .write_at_addr(&init_assembly, GuestAddress(0x1000))
                .expect("Failed to write init assembly to guest memory");
        })),
        ..Default::default()
    };

    run_tests!(
        setup,
        |_, regs, _| {
            // The output of the LSL instruction should be 4GB - 1.
            assert_eq!(regs.rax, 0xFFFFFFFF);
        },
        |_, exit, _, _: &mut dyn Vm| matches!(exit, VcpuExit::Hlt)
    );
}
