// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::CpuidResult;
use std::collections::BTreeMap;

use base::errno_result;
use base::error;
use base::ioctl;
use base::ioctl_with_mut_ptr;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ptr;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::AsRawDescriptor;
use base::Error;
use base::IoctlNr;
use base::MappedRegion;
use base::Result;
use data_model::vec_with_array_field;
use data_model::FlexibleArrayWrapper;
use kvm_sys::*;
use libc::E2BIG;
use libc::EIO;
use libc::ENXIO;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;

use super::Config;
use super::Kvm;
use super::KvmVcpu;
use super::KvmVm;
use crate::host_phys_addr_bits;
use crate::ClockState;
use crate::CpuId;
use crate::CpuIdEntry;
use crate::DebugRegs;
use crate::DescriptorTable;
use crate::DeviceKind;
use crate::Fpu;
use crate::HypervisorX86_64;
use crate::IoapicRedirectionTableEntry;
use crate::IoapicState;
use crate::IrqSourceChip;
use crate::LapicState;
use crate::PicSelect;
use crate::PicState;
use crate::PitChannelState;
use crate::PitState;
use crate::ProtectionType;
use crate::Regs;
use crate::Segment;
use crate::Sregs;
use crate::VcpuExit;
use crate::VcpuX86_64;
use crate::VmCap;
use crate::VmX86_64;
use crate::Xsave;
use crate::NUM_IOAPIC_PINS;

type KvmCpuId = FlexibleArrayWrapper<kvm_cpuid2, kvm_cpuid_entry2>;
const KVM_XSAVE_MAX_SIZE: usize = 4096;
const MSR_IA32_APICBASE: u32 = 0x0000001b;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuEvents {
    pub exception: VcpuExceptionState,
    pub interrupt: VcpuInterruptState,
    pub nmi: VcpuNmiState,
    pub sipi_vector: Option<u32>,
    pub smi: VcpuSmiState,
    pub triple_fault: VcpuTripleFaultState,
    pub exception_payload: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuExceptionState {
    pub injected: bool,
    pub nr: u8,
    pub has_error_code: bool,
    pub pending: Option<bool>,
    pub error_code: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuInterruptState {
    pub injected: bool,
    pub nr: u8,
    pub soft: bool,
    pub shadow: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuNmiState {
    pub injected: bool,
    pub pending: Option<bool>,
    pub masked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuSmiState {
    pub smm: Option<bool>,
    pub pending: bool,
    pub smm_inside_nmi: bool,
    pub latched_init: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuTripleFaultState {
    pub pending: Option<bool>,
}

pub fn get_cpuid_with_initial_capacity<T: AsRawDescriptor>(
    descriptor: &T,
    kind: IoctlNr,
    initial_capacity: usize,
) -> Result<CpuId> {
    let mut entries: usize = initial_capacity;

    loop {
        let mut kvm_cpuid = KvmCpuId::new(entries);

        let ret = {
            // SAFETY:
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the
            // memory allocated for the struct. The limit is read from nent within KvmCpuId,
            // which is set to the allocated size above.
            unsafe { ioctl_with_mut_ptr(descriptor, kind, kvm_cpuid.as_mut_ptr()) }
        };
        if ret < 0 {
            let err = Error::last();
            match err.errno() {
                E2BIG => {
                    // double the available memory for cpuid entries for kvm.
                    if let Some(val) = entries.checked_mul(2) {
                        entries = val;
                    } else {
                        return Err(err);
                    }
                }
                _ => return Err(err),
            }
        } else {
            return Ok(CpuId::from(&kvm_cpuid));
        }
    }
}

impl Kvm {
    pub fn get_cpuid(&self, kind: IoctlNr) -> Result<CpuId> {
        const KVM_MAX_ENTRIES: usize = 256;
        get_cpuid_with_initial_capacity(self, kind, KVM_MAX_ENTRIES)
    }

    // The x86 machine type is always 0. Protected VMs are not supported.
    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        if protection_type == ProtectionType::Unprotected {
            Ok(0)
        } else {
            error!("Protected mode is not supported on x86_64.");
            Err(Error::new(libc::EINVAL))
        }
    }

    /// Get the size of guest physical addresses in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // Assume the guest physical address size is the same as the host.
        host_phys_addr_bits()
    }
}

impl HypervisorX86_64 for Kvm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID())
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID())
    }

    fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        const MAX_KVM_MSR_ENTRIES: usize = 256;

        let mut msr_list = vec_with_array_field::<kvm_msr_list, u32>(MAX_KVM_MSR_ENTRIES);
        msr_list[0].nmsrs = MAX_KVM_MSR_ENTRIES as u32;

        let ret = {
            // SAFETY:
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
            // size (MAX_KVM_MSR_ENTRIES) above.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_MSR_INDEX_LIST(), &mut msr_list[0]) }
        };
        if ret < 0 {
            return errno_result();
        }

        let mut nmsrs = msr_list[0].nmsrs;

        // SAFETY:
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        let indices: &[u32] = unsafe {
            if nmsrs > MAX_KVM_MSR_ENTRIES as u32 {
                nmsrs = MAX_KVM_MSR_ENTRIES as u32;
            }
            msr_list[0].indices.as_slice(nmsrs as usize)
        };

        Ok(indices.to_vec())
    }
}

impl KvmVm {
    /// Does platform specific initialization for the KvmVm.
    pub fn init_arch(&self, _cfg: &Config) -> Result<()> {
        Ok(())
    }

    /// Whether running under pKVM.
    pub fn is_pkvm(&self) -> bool {
        false
    }

    /// Checks if a particular `VmCap` is available, or returns None if arch-independent
    /// Vm.check_capability() should handle the check.
    pub fn check_capability_arch(&self, c: VmCap) -> Option<bool> {
        match c {
            VmCap::PvClock => Some(true),
            _ => None,
        }
    }

    /// Returns the params to pass to KVM_CREATE_DEVICE for a `kind` device on this arch, or None to
    /// let the arch-independent `KvmVm::create_device` handle it.
    pub fn get_device_params_arch(&self, _kind: DeviceKind) -> Option<kvm_create_device> {
        None
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        let mut clock_data: kvm_clock_data = Default::default();
        let ret =
            // SAFETY:
            // Safe because we know that our file is a VM fd, we know the kernel will only write correct
            // amount of memory to our pointer, and we verify the return result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_CLOCK(), &mut clock_data) };
        if ret == 0 {
            Ok(ClockState::from(&clock_data))
        } else {
            errno_result()
        }
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.
    pub fn set_pvclock_arch(&self, state: &ClockState) -> Result<()> {
        let clock_data = kvm_clock_data::from(state);
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read correct
        // amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_CLOCK(), &clock_data) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of given interrupt controller by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_pic_state(&self, id: PicSelect) -> Result<kvm_pic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        let ret = {
            // SAFETY:
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state) }
        };
        if ret == 0 {
            Ok(
                // SAFETY:
                // Safe as we know that we are retrieving data related to the
                // PIC (primary or secondary) and not IOAPIC.
                unsafe { irqchip_state.chip.pic },
            )
        } else {
            errno_result()
        }
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_pic_state(&self, id: PicSelect, state: &kvm_pic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        irqchip_state.chip.pic = *state;
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the number of pins for emulated IO-APIC.
    pub fn get_ioapic_num_pins(&self) -> Result<usize> {
        Ok(NUM_IOAPIC_PINS)
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_ioapic_state(&self) -> Result<kvm_ioapic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        let ret = {
            // SAFETY:
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state) }
        };
        if ret == 0 {
            Ok(
                // SAFETY:
                // Safe as we know that we are retrieving data related to the
                // IOAPIC and not PIC.
                unsafe { irqchip_state.chip.ioapic },
            )
        } else {
            errno_result()
        }
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_ioapic_state(&self, state: &kvm_ioapic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        irqchip_state.chip.ioapic = *state;
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn create_pit(&self) -> Result<()> {
        let pit_config = kvm_pit_config::default();
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of PIT by issuing KVM_GET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        let mut pit_state = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only write
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_PIT2(), &mut pit_state) };
        if ret == 0 {
            Ok(pit_state)
        } else {
            errno_result()
        }
    }

    /// Sets the state of PIT by issuing KVM_SET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_PIT2(), pit_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Set MSR_PLATFORM_INFO read access.
    pub fn set_platform_info_read_access(&self, allow_read: bool) -> Result<()> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_MSR_PLATFORM_INFO,
            ..Default::default()
        };
        cap.args[0] = allow_read as u64;

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know that the
        // kernel will only read correct amount of memory from our pointer, and
        // we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), &cap) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }

    /// Enable support for split-irqchip.
    pub fn enable_split_irqchip(&self, ioapic_pins: usize) -> Result<()> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = ioapic_pins as u64;
        // SAFETY:
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), &cap) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }
}

impl VmX86_64 for KvmVm {
    fn get_hypervisor(&self) -> &dyn HypervisorX86_64 {
        &self.kvm
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuX86_64>> {
        // create_vcpu is declared separately in VmAArch64 and VmX86, so it can return VcpuAArch64
        // or VcpuX86.  But both use the same implementation in KvmVm::create_vcpu.
        Ok(Box::new(KvmVm::create_kvm_vcpu(self, id)?))
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_TSS_ADDR ioctl.
    fn set_tss_addr(&self, addr: GuestAddress) -> Result<()> {
        // SAFETY:
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), addr.offset()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the address of a one-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_IDENTITY_MAP_ADDR ioctl.
    fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()> {
        // SAFETY:
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IDENTITY_MAP_ADDR(), &addr.offset()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl KvmVcpu {
    /// Handles a `KVM_EXIT_SYSTEM_EVENT` with event type `KVM_SYSTEM_EVENT_RESET` with the given
    /// event flags and returns the appropriate `VcpuExit` value for the run loop to handle.
    pub fn system_event_reset(&self, _event_flags: u64) -> Result<VcpuExit> {
        Ok(VcpuExit::SystemEventReset)
    }

    /// Gets the Xsave size by checking the extension KVM_CAP_XSAVE2.
    ///
    /// Size should always be >=0. If size is negative, an error occurred.
    /// If size <= 4096, XSAVE2 is not supported by the CPU or the kernel. KVM_XSAVE_MAX_SIZE is
    /// returned (4096).
    /// Otherwise, the size will be returned.
    fn xsave_size(&self) -> Result<usize> {
        let size = {
            // SAFETY:
            // Safe because we know that our file is a valid VM fd
            unsafe { ioctl_with_val(&self.vm, KVM_CHECK_EXTENSION(), KVM_CAP_XSAVE2 as u64) }
        };
        if size < 0 {
            return errno_result();
        }
        // Safe to unwrap since we already tested for negative values
        let size: usize = size.try_into().unwrap();
        Ok(size.max(KVM_XSAVE_MAX_SIZE))
    }

    #[inline]
    pub(crate) fn handle_vm_exit_arch(&self, run: &mut kvm_run) -> Option<VcpuExit> {
        match run.exit_reason {
            KVM_EXIT_IO => Some(VcpuExit::Io),
            KVM_EXIT_IOAPIC_EOI => {
                // SAFETY:
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let vector = unsafe { run.__bindgen_anon_1.eoi.vector };
                Some(VcpuExit::IoapicEoi { vector })
            }
            KVM_EXIT_HLT => Some(VcpuExit::Hlt),
            KVM_EXIT_SET_TPR => Some(VcpuExit::SetTpr),
            KVM_EXIT_TPR_ACCESS => Some(VcpuExit::TprAccess),
            KVM_EXIT_X86_BUS_LOCK => Some(VcpuExit::BusLock),
            _ => None,
        }
    }
}

impl VcpuX86_64 for KvmVcpu {
    #[allow(clippy::cast_ptr_alignment)]
    fn set_interrupt_window_requested(&self, requested: bool) {
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.request_interrupt_window = requested.into();
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn ready_for_interrupt(&self) -> bool {
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.ready_for_interrupt_injection != 0 && run.if_flag != 0
    }

    /// Use the KVM_INTERRUPT ioctl to inject the specified interrupt vector.
    ///
    /// While this ioctl exists on PPC and MIPS as well as x86, the semantics are different and
    /// ChromeOS doesn't support PPC or MIPS.
    fn interrupt(&self, irq: u32) -> Result<()> {
        let interrupt = kvm_interrupt { irq };
        // SAFETY:
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_INTERRUPT(), &interrupt) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn inject_nmi(&self) -> Result<()> {
        // SAFETY:
        // Safe because we know that our file is a VCPU fd.
        let ret = unsafe { ioctl(self, KVM_NMI()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_regs(&self) -> Result<Regs> {
        let mut regs: kvm_regs = Default::default();
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only read
            // the correct amount of memory from our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) }
        };
        if ret == 0 {
            Ok(Regs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_regs(&self, regs: &Regs) -> Result<()> {
        let regs = kvm_regs::from(regs);
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only read
            // the correct amount of memory from our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_ref(self, KVM_SET_REGS(), &regs) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_sregs(&self) -> Result<Sregs> {
        let mut regs: kvm_sregs = Default::default();
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only write
            // the correct amount of memory to our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) }
        };
        if ret == 0 {
            Ok(Sregs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_sregs(&self, sregs: &Sregs) -> Result<()> {
        // Get the current `kvm_sregs` so we can use its `apic_base` and `interrupt_bitmap`, which
        // are not present in `Sregs`.
        let mut kvm_sregs: kvm_sregs = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut kvm_sregs) };
        if ret != 0 {
            return errno_result();
        }

        kvm_sregs.cs = kvm_segment::from(&sregs.cs);
        kvm_sregs.ds = kvm_segment::from(&sregs.ds);
        kvm_sregs.es = kvm_segment::from(&sregs.es);
        kvm_sregs.fs = kvm_segment::from(&sregs.fs);
        kvm_sregs.gs = kvm_segment::from(&sregs.gs);
        kvm_sregs.ss = kvm_segment::from(&sregs.ss);
        kvm_sregs.tr = kvm_segment::from(&sregs.tr);
        kvm_sregs.ldt = kvm_segment::from(&sregs.ldt);
        kvm_sregs.gdt = kvm_dtable::from(&sregs.gdt);
        kvm_sregs.idt = kvm_dtable::from(&sregs.idt);
        kvm_sregs.cr0 = sregs.cr0;
        kvm_sregs.cr2 = sregs.cr2;
        kvm_sregs.cr3 = sregs.cr3;
        kvm_sregs.cr4 = sregs.cr4;
        kvm_sregs.cr8 = sregs.cr8;
        kvm_sregs.efer = sregs.efer;

        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), &kvm_sregs) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_fpu(&self) -> Result<Fpu> {
        let mut fpu: kvm_fpu = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu) };
        if ret == 0 {
            Ok(Fpu::from(&fpu))
        } else {
            errno_result()
        }
    }

    fn set_fpu(&self, fpu: &Fpu) -> Result<()> {
        let fpu = kvm_fpu::from(fpu);
        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            unsafe { ioctl_with_ref(self, KVM_SET_FPU(), &fpu) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// If the VM reports using XSave2, the function will call XSave2.
    fn get_xsave(&self) -> Result<Xsave> {
        let size = self.xsave_size()?;
        let ioctl_nr = if size > KVM_XSAVE_MAX_SIZE {
            KVM_GET_XSAVE2()
        } else {
            KVM_GET_XSAVE()
        };
        let mut xsave = Xsave::new(size);

        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ptr(self, ioctl_nr, xsave.as_mut_ptr()) };
        if ret == 0 {
            Ok(xsave)
        } else {
            errno_result()
        }
    }

    fn set_xsave(&self, xsave: &Xsave) -> Result<()> {
        let size = self.xsave_size()?;
        // Ensure xsave is the same size as used in get_xsave.
        // Return err if sizes don't match => not the same extensions are enabled for CPU.
        if xsave.len() != size {
            return Err(Error::new(EIO));
        }

        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        // Because of the len check above, and because the layout of `struct kvm_xsave` is
        // compatible with a slice of `u32`, we can pass the pointer to `xsave` directly.
        let ret = unsafe { ioctl_with_ptr(self, KVM_SET_XSAVE(), xsave.as_ptr()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_interrupt_state(&self) -> Result<serde_json::Value> {
        let mut vcpu_evts: kvm_vcpu_events = Default::default();
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only write
            // the correct amount of memory to our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_VCPU_EVENTS(), &mut vcpu_evts) }
        };
        if ret == 0 {
            Ok(
                serde_json::to_value(VcpuEvents::from(&vcpu_evts)).map_err(|e| {
                    error!("failed to serialize vcpu_events: {:?}", e);
                    Error::new(EIO)
                })?,
            )
        } else {
            errno_result()
        }
    }

    fn set_interrupt_state(&self, data: serde_json::Value) -> Result<()> {
        let vcpu_events =
            kvm_vcpu_events::from(&serde_json::from_value::<VcpuEvents>(data).map_err(|e| {
                error!("failed to deserialize vcpu_events: {:?}", e);
                Error::new(EIO)
            })?);
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only read
            // the correct amount of memory from our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_ref(self, KVM_SET_VCPU_EVENTS(), &vcpu_events) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_debugregs(&self) -> Result<DebugRegs> {
        let mut regs: kvm_debugregs = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_DEBUGREGS(), &mut regs) };
        if ret == 0 {
            Ok(DebugRegs::from(&regs))
        } else {
            errno_result()
        }
    }

    fn set_debugregs(&self, dregs: &DebugRegs) -> Result<()> {
        let dregs = kvm_debugregs::from(dregs);
        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_debugregs struct.
            unsafe { ioctl_with_ref(self, KVM_SET_DEBUGREGS(), &dregs) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_xcrs(&self) -> Result<BTreeMap<u32, u64>> {
        let mut regs: kvm_xcrs = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_XCRS(), &mut regs) };
        if ret < 0 {
            return errno_result();
        }

        Ok(regs
            .xcrs
            .iter()
            .take(regs.nr_xcrs as usize)
            .map(|kvm_xcr| (kvm_xcr.xcr, kvm_xcr.value))
            .collect())
    }

    fn set_xcr(&self, xcr_index: u32, value: u64) -> Result<()> {
        let mut kvm_xcr = kvm_xcrs {
            nr_xcrs: 1,
            ..Default::default()
        };
        kvm_xcr.xcrs[0].xcr = xcr_index;
        kvm_xcr.xcrs[0].value = value;

        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_xcrs struct.
            unsafe { ioctl_with_ref(self, KVM_SET_XCRS(), &kvm_xcr) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_msr(&self, msr_index: u32) -> Result<u64> {
        let mut msrs = vec_with_array_field::<kvm_msrs, kvm_msr_entry>(1);
        msrs[0].nmsrs = 1;

        // SAFETY: We initialize a one-element array using `vec_with_array_field` above.
        unsafe {
            let msr_entries = msrs[0].entries.as_mut_slice(1);
            msr_entries[0].index = msr_index;
        }

        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read or write past the end of the kvm_msrs struct.
            unsafe { ioctl_with_ref(self, KVM_GET_MSRS(), &msrs[0]) }
        };
        if ret < 0 {
            return errno_result();
        }

        // KVM_GET_MSRS returns the number of msr entries written.
        if ret != 1 {
            return Err(base::Error::new(libc::ENOENT));
        }

        // SAFETY:
        // Safe because we trust the kernel to return the correct array length on success.
        let value = unsafe {
            let msr_entries = msrs[0].entries.as_slice(1);
            msr_entries[0].data
        };

        Ok(value)
    }

    fn get_all_msrs(&self) -> Result<BTreeMap<u32, u64>> {
        let msr_index_list = self.kvm.get_msr_index_list()?;
        let mut kvm_msrs = vec_with_array_field::<kvm_msrs, kvm_msr_entry>(msr_index_list.len());
        kvm_msrs[0].nmsrs = msr_index_list.len() as u32;
        // SAFETY:
        // Mapping the unsized array to a slice is unsafe because the length isn't known.
        // Providing the length used to create the struct guarantees the entire slice is valid.
        unsafe {
            kvm_msrs[0]
                .entries
                .as_mut_slice(msr_index_list.len())
                .iter_mut()
                .zip(msr_index_list.iter())
                .for_each(|(msr_entry, msr_index)| msr_entry.index = *msr_index);
        }

        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read or write past the end of the kvm_msrs struct.
            unsafe { ioctl_with_ref(self, KVM_GET_MSRS(), &kvm_msrs[0]) }
        };
        if ret < 0 {
            return errno_result();
        }

        // KVM_GET_MSRS returns the number of msr entries written.
        let count = ret as usize;
        if count != msr_index_list.len() {
            error!(
                "failed to get all MSRs: requested {}, got {}",
                msr_index_list.len(),
                count,
            );
            return Err(base::Error::new(libc::EPERM));
        }

        // SAFETY:
        // Safe because we trust the kernel to return the correct array length on success.
        let msrs = unsafe {
            BTreeMap::from_iter(
                kvm_msrs[0]
                    .entries
                    .as_slice(count)
                    .iter()
                    .map(|kvm_msr| (kvm_msr.index, kvm_msr.data)),
            )
        };

        Ok(msrs)
    }

    fn set_msr(&self, msr_index: u32, value: u64) -> Result<()> {
        let mut kvm_msrs = vec_with_array_field::<kvm_msrs, kvm_msr_entry>(1);
        kvm_msrs[0].nmsrs = 1;

        // SAFETY: We initialize a one-element array using `vec_with_array_field` above.
        unsafe {
            let msr_entries = kvm_msrs[0].entries.as_mut_slice(1);
            msr_entries[0].index = msr_index;
            msr_entries[0].data = value;
        }

        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            unsafe { ioctl_with_ref(self, KVM_SET_MSRS(), &kvm_msrs[0]) }
        };
        if ret < 0 {
            return errno_result();
        }

        // KVM_SET_MSRS returns the number of msr entries written.
        if ret != 1 {
            error!("failed to set MSR {:#x} to {:#x}", msr_index, value);
            return Err(base::Error::new(libc::EPERM));
        }

        Ok(())
    }

    fn set_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        let cpuid = KvmCpuId::from(cpuid);
        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            unsafe { ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_ptr()) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()> {
        use kvm_sys::*;
        let mut dbg: kvm_guest_debug = Default::default();

        if addrs.len() > 4 {
            error!(
                "Support 4 breakpoints at most but {} addresses are passed",
                addrs.len()
            );
            return Err(base::Error::new(libc::EINVAL));
        }

        dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        if enable_singlestep {
            dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        }

        // Set bits 9 and 10.
        // bit 9: GE (global exact breakpoint enable) flag.
        // bit 10: always 1.
        dbg.arch.debugreg[7] = 0x0600;

        for (i, addr) in addrs.iter().enumerate() {
            dbg.arch.debugreg[i] = addr.0;
            // Set global breakpoint enable flag
            dbg.arch.debugreg[7] |= 2 << (i * 2);
        }

        let ret = {
            // SAFETY:
            // Here we trust the kernel not to read past the end of the kvm_guest_debug struct.
            unsafe { ioctl_with_ref(self, KVM_SET_GUEST_DEBUG(), &dbg) }
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// KVM does not support the VcpuExit::Cpuid exit type.
    fn handle_cpuid(&mut self, _entry: &CpuIdEntry) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    fn restore_timekeeping(&self, _host_tsc_reference_moment: u64, _tsc_offset: u64) -> Result<()> {
        // On KVM, the TSC MSR is restored as part of SET_MSRS, and no further action is required.
        Ok(())
    }
}

impl KvmVcpu {
    /// X86 specific call to get the state of the "Local Advanced Programmable Interrupt
    /// Controller".
    ///
    /// See the documentation for KVM_GET_LAPIC.
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic: kvm_lapic_state = Default::default();

        let ret = {
            // SAFETY:
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic) }
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(klapic)
    }

    /// X86 specific call to set the state of the "Local Advanced Programmable Interrupt
    /// Controller".
    ///
    /// See the documentation for KVM_SET_LAPIC.
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = {
            // SAFETY:
            // The ioctl is safe because the kernel will only read from the klapic struct.
            unsafe { ioctl_with_ref(self, KVM_SET_LAPIC(), klapic) }
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// X86 specific call to get the value of the APIC_BASE MSR.
    ///
    /// See the documentation for The kvm_run structure, and for KVM_GET_LAPIC.
    pub fn get_apic_base(&self) -> Result<u64> {
        self.get_msr(MSR_IA32_APICBASE)
    }

    /// X86 specific call to set the value of the APIC_BASE MSR.
    ///
    /// See the documentation for The kvm_run structure, and for KVM_GET_LAPIC.
    pub fn set_apic_base(&self, apic_base: u64) -> Result<()> {
        self.set_msr(MSR_IA32_APICBASE, apic_base)
    }

    /// Call to get pending interrupts acknowledged by the APIC but not yet injected into the CPU.
    ///
    /// See the documentation for KVM_GET_SREGS.
    pub fn get_interrupt_bitmap(&self) -> Result<[u64; 4usize]> {
        let mut regs: kvm_sregs = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret >= 0 {
            Ok(regs.interrupt_bitmap)
        } else {
            errno_result()
        }
    }

    /// Call to set pending interrupts acknowledged by the APIC but not yet injected into the CPU.
    ///
    /// See the documentation for KVM_GET_SREGS.
    pub fn set_interrupt_bitmap(&self, interrupt_bitmap: [u64; 4usize]) -> Result<()> {
        // Potentially racy code. Vcpu registers are set in a separate thread and this could result
        // in Sregs being modified from the Vcpu initialization thread and the Irq restoring
        // thread.
        let mut regs: kvm_sregs = Default::default();
        // SAFETY:
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret >= 0 {
            regs.interrupt_bitmap = interrupt_bitmap;
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only read
            // the correct amount of memory from our pointer, and we verify the return
            // result.
            let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), &regs) };
            if ret >= 0 {
                Ok(())
            } else {
                errno_result()
            }
        } else {
            errno_result()
        }
    }
}

impl<'a> From<&'a KvmCpuId> for CpuId {
    fn from(kvm_cpuid: &'a KvmCpuId) -> CpuId {
        let kvm_entries = kvm_cpuid.entries_slice();
        let mut cpu_id_entries = Vec::with_capacity(kvm_entries.len());

        for entry in kvm_entries {
            let cpu_id_entry = CpuIdEntry {
                function: entry.function,
                index: entry.index,
                flags: entry.flags,
                cpuid: CpuidResult {
                    eax: entry.eax,
                    ebx: entry.ebx,
                    ecx: entry.ecx,
                    edx: entry.edx,
                },
            };
            cpu_id_entries.push(cpu_id_entry)
        }
        CpuId { cpu_id_entries }
    }
}

impl From<&CpuId> for KvmCpuId {
    fn from(cpuid: &CpuId) -> KvmCpuId {
        let mut kvm = KvmCpuId::new(cpuid.cpu_id_entries.len());
        let entries = kvm.mut_entries_slice();
        for (i, &e) in cpuid.cpu_id_entries.iter().enumerate() {
            entries[i] = kvm_cpuid_entry2 {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.cpuid.eax,
                ebx: e.cpuid.ebx,
                ecx: e.cpuid.ecx,
                edx: e.cpuid.edx,
                ..Default::default()
            };
        }
        kvm
    }
}

impl From<&ClockState> for kvm_clock_data {
    fn from(state: &ClockState) -> Self {
        kvm_clock_data {
            clock: state.clock,
            ..Default::default()
        }
    }
}

impl From<&kvm_clock_data> for ClockState {
    fn from(clock_data: &kvm_clock_data) -> Self {
        ClockState {
            clock: clock_data.clock,
        }
    }
}

impl From<&kvm_pic_state> for PicState {
    fn from(item: &kvm_pic_state) -> Self {
        PicState {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select != 0,
            poll: item.poll != 0,
            special_mask: item.special_mask != 0,
            init_state: item.init_state.into(),
            auto_eoi: item.auto_eoi != 0,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi != 0,
            special_fully_nested_mode: item.special_fully_nested_mode != 0,
            use_4_byte_icw: item.init4 != 0,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&PicState> for kvm_pic_state {
    fn from(item: &PicState) -> Self {
        kvm_pic_state {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select as u8,
            poll: item.poll as u8,
            special_mask: item.special_mask as u8,
            init_state: item.init_state as u8,
            auto_eoi: item.auto_eoi as u8,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi as u8,
            special_fully_nested_mode: item.special_fully_nested_mode as u8,
            init4: item.use_4_byte_icw as u8,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&kvm_ioapic_state> for IoapicState {
    fn from(item: &kvm_ioapic_state) -> Self {
        let mut state = IoapicState {
            base_address: item.base_address,
            ioregsel: item.ioregsel as u8,
            ioapicid: item.id,
            current_interrupt_level_bitmap: item.irr,
            redirect_table: [IoapicRedirectionTableEntry::default(); NUM_IOAPIC_PINS],
        };
        for (in_state, out_state) in item.redirtbl.iter().zip(state.redirect_table.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&IoapicRedirectionTableEntry> for kvm_ioapic_state__bindgen_ty_1 {
    fn from(item: &IoapicRedirectionTableEntry) -> Self {
        kvm_ioapic_state__bindgen_ty_1 {
            // IoapicRedirectionTableEntry layout matches the exact bit layout of a hardware
            // ioapic redirection table entry, so we can simply do a 64-bit copy
            bits: item.get(0, 64),
        }
    }
}

impl From<&kvm_ioapic_state__bindgen_ty_1> for IoapicRedirectionTableEntry {
    fn from(item: &kvm_ioapic_state__bindgen_ty_1) -> Self {
        let mut entry = IoapicRedirectionTableEntry::default();
        // SAFETY:
        // Safe because the 64-bit layout of the IoapicRedirectionTableEntry matches the kvm_sys
        // table entry layout
        entry.set(0, 64, unsafe { item.bits });
        entry
    }
}

impl From<&IoapicState> for kvm_ioapic_state {
    fn from(item: &IoapicState) -> Self {
        let mut state = kvm_ioapic_state {
            base_address: item.base_address,
            ioregsel: item.ioregsel as u32,
            id: item.ioapicid,
            irr: item.current_interrupt_level_bitmap,
            ..Default::default()
        };
        for (in_state, out_state) in item.redirect_table.iter().zip(state.redirtbl.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&LapicState> for kvm_lapic_state {
    fn from(item: &LapicState) -> Self {
        let mut state = kvm_lapic_state::default();
        // There are 64 lapic registers
        for (reg, value) in item.regs.iter().enumerate() {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;
            let regs_slice = &mut state.regs[reg_offset..reg_offset + 4];

            // to_le_bytes() produces an array of u8, not i8(c_char), so we can't directly use
            // copy_from_slice().
            for (i, v) in value.to_le_bytes().iter().enumerate() {
                regs_slice[i] = *v as i8;
            }
        }
        state
    }
}

impl From<&kvm_lapic_state> for LapicState {
    fn from(item: &kvm_lapic_state) -> Self {
        let mut state = LapicState { regs: [0; 64] };
        // There are 64 lapic registers
        for reg in 0..64 {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;

            // from_le_bytes() only works on arrays of u8, not i8(c_char).
            let reg_slice = &item.regs[reg_offset..reg_offset + 4];
            let mut bytes = [0u8; 4];
            for i in 0..4 {
                bytes[i] = reg_slice[i] as u8;
            }
            state.regs[reg] = u32::from_le_bytes(bytes);
        }
        state
    }
}

impl From<&PitState> for kvm_pit_state2 {
    fn from(item: &PitState) -> Self {
        kvm_pit_state2 {
            channels: [
                kvm_pit_channel_state::from(&item.channels[0]),
                kvm_pit_channel_state::from(&item.channels[1]),
                kvm_pit_channel_state::from(&item.channels[2]),
            ],
            flags: item.flags,
            ..Default::default()
        }
    }
}

impl From<&kvm_pit_state2> for PitState {
    fn from(item: &kvm_pit_state2) -> Self {
        PitState {
            channels: [
                PitChannelState::from(&item.channels[0]),
                PitChannelState::from(&item.channels[1]),
                PitChannelState::from(&item.channels[2]),
            ],
            flags: item.flags,
        }
    }
}

impl From<&PitChannelState> for kvm_pit_channel_state {
    fn from(item: &PitChannelState) -> Self {
        kvm_pit_channel_state {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched as u8,
            status_latched: item.status_latched as u8,
            status: item.status,
            read_state: item.read_state as u8,
            write_state: item.write_state as u8,
            // kvm's write_latch only stores the low byte of the reload value
            write_latch: item.reload_value as u8,
            rw_mode: item.rw_mode as u8,
            mode: item.mode,
            bcd: item.bcd as u8,
            gate: item.gate as u8,
            count_load_time: item.count_load_time as i64,
        }
    }
}

impl From<&kvm_pit_channel_state> for PitChannelState {
    fn from(item: &kvm_pit_channel_state) -> Self {
        PitChannelState {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched.into(),
            status_latched: item.status_latched != 0,
            status: item.status,
            read_state: item.read_state.into(),
            write_state: item.write_state.into(),
            // kvm's write_latch only stores the low byte of the reload value
            reload_value: item.write_latch as u16,
            rw_mode: item.rw_mode.into(),
            mode: item.mode,
            bcd: item.bcd != 0,
            gate: item.gate != 0,
            count_load_time: item.count_load_time as u64,
        }
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between x86_64 and aarch64 because the irqchip KVM constants are not defined on
// all architectures.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        IrqSourceChip::PicPrimary => KVM_IRQCHIP_PIC_MASTER,
        IrqSourceChip::PicSecondary => KVM_IRQCHIP_PIC_SLAVE,
        IrqSourceChip::Ioapic => KVM_IRQCHIP_IOAPIC,
        _ => {
            error!("Invalid IrqChipSource for X86 {:?}", chip);
            0
        }
    }
}

impl From<&kvm_regs> for Regs {
    fn from(r: &kvm_regs) -> Self {
        Regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        }
    }
}

impl From<&Regs> for kvm_regs {
    fn from(r: &Regs) -> Self {
        kvm_regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        }
    }
}

impl From<&VcpuEvents> for kvm_vcpu_events {
    fn from(ve: &VcpuEvents) -> Self {
        let mut kvm_ve: kvm_vcpu_events = Default::default();

        kvm_ve.exception.injected = ve.exception.injected as u8;
        kvm_ve.exception.nr = ve.exception.nr;
        kvm_ve.exception.has_error_code = ve.exception.has_error_code as u8;
        if let Some(pending) = ve.exception.pending {
            kvm_ve.exception.pending = pending as u8;
            if ve.exception_payload.is_some() {
                kvm_ve.exception_has_payload = true as u8;
            }
            kvm_ve.exception_payload = ve.exception_payload.unwrap_or(0);
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_PAYLOAD;
        }
        kvm_ve.exception.error_code = ve.exception.error_code;

        kvm_ve.interrupt.injected = ve.interrupt.injected as u8;
        kvm_ve.interrupt.nr = ve.interrupt.nr;
        kvm_ve.interrupt.soft = ve.interrupt.soft as u8;
        if let Some(shadow) = ve.interrupt.shadow {
            kvm_ve.interrupt.shadow = shadow;
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_SHADOW;
        }

        kvm_ve.nmi.injected = ve.nmi.injected as u8;
        if let Some(pending) = ve.nmi.pending {
            kvm_ve.nmi.pending = pending as u8;
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_NMI_PENDING;
        }
        kvm_ve.nmi.masked = ve.nmi.masked as u8;

        if let Some(sipi_vector) = ve.sipi_vector {
            kvm_ve.sipi_vector = sipi_vector;
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_SIPI_VECTOR;
        }

        if let Some(smm) = ve.smi.smm {
            kvm_ve.smi.smm = smm as u8;
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_SMM;
        }
        kvm_ve.smi.pending = ve.smi.pending as u8;
        kvm_ve.smi.smm_inside_nmi = ve.smi.smm_inside_nmi as u8;
        kvm_ve.smi.latched_init = ve.smi.latched_init;

        if let Some(pending) = ve.triple_fault.pending {
            kvm_ve.triple_fault.pending = pending as u8;
            kvm_ve.flags |= KVM_VCPUEVENT_VALID_TRIPLE_FAULT;
        }
        kvm_ve
    }
}

impl From<&kvm_vcpu_events> for VcpuEvents {
    fn from(ve: &kvm_vcpu_events) -> Self {
        let exception = VcpuExceptionState {
            injected: ve.exception.injected != 0,
            nr: ve.exception.nr,
            has_error_code: ve.exception.has_error_code != 0,
            pending: if ve.flags & KVM_VCPUEVENT_VALID_PAYLOAD != 0 {
                Some(ve.exception.pending != 0)
            } else {
                None
            },
            error_code: ve.exception.error_code,
        };

        let interrupt = VcpuInterruptState {
            injected: ve.interrupt.injected != 0,
            nr: ve.interrupt.nr,
            soft: ve.interrupt.soft != 0,
            shadow: if ve.flags & KVM_VCPUEVENT_VALID_SHADOW != 0 {
                Some(ve.interrupt.shadow)
            } else {
                None
            },
        };

        let nmi = VcpuNmiState {
            injected: ve.interrupt.injected != 0,
            pending: if ve.flags & KVM_VCPUEVENT_VALID_NMI_PENDING != 0 {
                Some(ve.nmi.pending != 0)
            } else {
                None
            },
            masked: ve.nmi.masked != 0,
        };

        let sipi_vector = if ve.flags & KVM_VCPUEVENT_VALID_SIPI_VECTOR != 0 {
            Some(ve.sipi_vector)
        } else {
            None
        };

        let smi = VcpuSmiState {
            smm: if ve.flags & KVM_VCPUEVENT_VALID_SMM != 0 {
                Some(ve.smi.smm != 0)
            } else {
                None
            },
            pending: ve.smi.pending != 0,
            smm_inside_nmi: ve.smi.smm_inside_nmi != 0,
            latched_init: ve.smi.latched_init,
        };

        let triple_fault = VcpuTripleFaultState {
            pending: if ve.flags & KVM_VCPUEVENT_VALID_TRIPLE_FAULT != 0 {
                Some(ve.triple_fault.pending != 0)
            } else {
                None
            },
        };

        let exception_payload = if ve.flags & KVM_VCPUEVENT_VALID_PAYLOAD != 0 {
            Some(ve.exception_payload)
        } else {
            None
        };

        VcpuEvents {
            exception,
            interrupt,
            nmi,
            sipi_vector,
            smi,
            triple_fault,
            exception_payload,
        }
    }
}

impl From<&kvm_segment> for Segment {
    fn from(s: &kvm_segment) -> Self {
        Segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
        }
    }
}

impl From<&Segment> for kvm_segment {
    fn from(s: &Segment) -> Self {
        kvm_segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: match s.present {
                0 => 1,
                _ => 0,
            },
            ..Default::default()
        }
    }
}

impl From<&kvm_dtable> for DescriptorTable {
    fn from(dt: &kvm_dtable) -> Self {
        DescriptorTable {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

impl From<&DescriptorTable> for kvm_dtable {
    fn from(dt: &DescriptorTable) -> Self {
        kvm_dtable {
            base: dt.base,
            limit: dt.limit,
            ..Default::default()
        }
    }
}

impl From<&kvm_sregs> for Sregs {
    fn from(r: &kvm_sregs) -> Self {
        Sregs {
            cs: Segment::from(&r.cs),
            ds: Segment::from(&r.ds),
            es: Segment::from(&r.es),
            fs: Segment::from(&r.fs),
            gs: Segment::from(&r.gs),
            ss: Segment::from(&r.ss),
            tr: Segment::from(&r.tr),
            ldt: Segment::from(&r.ldt),
            gdt: DescriptorTable::from(&r.gdt),
            idt: DescriptorTable::from(&r.idt),
            cr0: r.cr0,
            cr2: r.cr2,
            cr3: r.cr3,
            cr4: r.cr4,
            cr8: r.cr8,
            efer: r.efer,
        }
    }
}

impl From<&kvm_fpu> for Fpu {
    fn from(r: &kvm_fpu) -> Self {
        Fpu {
            fpr: r.fpr,
            fcw: r.fcw,
            fsw: r.fsw,
            ftwx: r.ftwx,
            last_opcode: r.last_opcode,
            last_ip: r.last_ip,
            last_dp: r.last_dp,
            xmm: r.xmm,
            mxcsr: r.mxcsr,
        }
    }
}

impl From<&Fpu> for kvm_fpu {
    fn from(r: &Fpu) -> Self {
        kvm_fpu {
            fpr: r.fpr,
            fcw: r.fcw,
            fsw: r.fsw,
            ftwx: r.ftwx,
            last_opcode: r.last_opcode,
            last_ip: r.last_ip,
            last_dp: r.last_dp,
            xmm: r.xmm,
            mxcsr: r.mxcsr,
            ..Default::default()
        }
    }
}

impl From<&kvm_debugregs> for DebugRegs {
    fn from(r: &kvm_debugregs) -> Self {
        DebugRegs {
            db: r.db,
            dr6: r.dr6,
            dr7: r.dr7,
        }
    }
}

impl From<&DebugRegs> for kvm_debugregs {
    fn from(r: &DebugRegs) -> Self {
        kvm_debugregs {
            db: r.db,
            dr6: r.dr6,
            dr7: r.dr7,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_event_to_from() {
        // All data is random.
        let mut kvm_ve: kvm_vcpu_events = Default::default();
        kvm_ve.exception.injected = 1;
        kvm_ve.exception.nr = 65;
        kvm_ve.exception.has_error_code = 1;
        kvm_ve.exception.error_code = 110;
        kvm_ve.exception.pending = 1;

        kvm_ve.interrupt.injected = 1;
        kvm_ve.interrupt.nr = 100;
        kvm_ve.interrupt.soft = 1;
        kvm_ve.interrupt.shadow = 114;

        kvm_ve.nmi.injected = 1;
        kvm_ve.nmi.pending = 1;
        kvm_ve.nmi.masked = 0;

        kvm_ve.sipi_vector = 105;

        kvm_ve.smi.smm = 1;
        kvm_ve.smi.pending = 1;
        kvm_ve.smi.smm_inside_nmi = 1;
        kvm_ve.smi.latched_init = 100;

        kvm_ve.triple_fault.pending = 0;

        kvm_ve.exception_payload = 33;
        kvm_ve.exception_has_payload = 1;

        kvm_ve.flags = 0
            | KVM_VCPUEVENT_VALID_PAYLOAD
            | KVM_VCPUEVENT_VALID_SMM
            | KVM_VCPUEVENT_VALID_NMI_PENDING
            | KVM_VCPUEVENT_VALID_SIPI_VECTOR
            | KVM_VCPUEVENT_VALID_SHADOW;

        let ve: VcpuEvents = VcpuEvents::from(&kvm_ve);
        assert_eq!(ve.exception.injected, true);
        assert_eq!(ve.exception.nr, 65);
        assert_eq!(ve.exception.has_error_code, true);
        assert_eq!(ve.exception.error_code, 110);
        assert_eq!(ve.exception.pending.unwrap(), true);

        assert_eq!(ve.interrupt.injected, true);
        assert_eq!(ve.interrupt.nr, 100);
        assert_eq!(ve.interrupt.soft, true);
        assert_eq!(ve.interrupt.shadow.unwrap(), 114);

        assert_eq!(ve.nmi.injected, true);
        assert_eq!(ve.nmi.pending.unwrap(), true);
        assert_eq!(ve.nmi.masked, false);

        assert_eq!(ve.sipi_vector.unwrap(), 105);

        assert_eq!(ve.smi.smm.unwrap(), true);
        assert_eq!(ve.smi.pending, true);
        assert_eq!(ve.smi.smm_inside_nmi, true);
        assert_eq!(ve.smi.latched_init, 100);

        assert_eq!(ve.triple_fault.pending, None);

        assert_eq!(ve.exception_payload.unwrap(), 33);

        let kvm_ve_restored: kvm_vcpu_events = kvm_vcpu_events::from(&ve);
        assert_eq!(kvm_ve_restored.exception.injected, 1);
        assert_eq!(kvm_ve_restored.exception.nr, 65);
        assert_eq!(kvm_ve_restored.exception.has_error_code, 1);
        assert_eq!(kvm_ve_restored.exception.error_code, 110);
        assert_eq!(kvm_ve_restored.exception.pending, 1);

        assert_eq!(kvm_ve_restored.interrupt.injected, 1);
        assert_eq!(kvm_ve_restored.interrupt.nr, 100);
        assert_eq!(kvm_ve_restored.interrupt.soft, 1);
        assert_eq!(kvm_ve_restored.interrupt.shadow, 114);

        assert_eq!(kvm_ve_restored.nmi.injected, 1);
        assert_eq!(kvm_ve_restored.nmi.pending, 1);
        assert_eq!(kvm_ve_restored.nmi.masked, 0);

        assert_eq!(kvm_ve_restored.sipi_vector, 105);

        assert_eq!(kvm_ve_restored.smi.smm, 1);
        assert_eq!(kvm_ve_restored.smi.pending, 1);
        assert_eq!(kvm_ve_restored.smi.smm_inside_nmi, 1);
        assert_eq!(kvm_ve_restored.smi.latched_init, 100);

        assert_eq!(kvm_ve_restored.triple_fault.pending, 0);

        assert_eq!(kvm_ve_restored.exception_payload, 33);
        assert_eq!(kvm_ve_restored.exception_has_payload, 1);
    }
}
