// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::ffi::c_void;
use std::arch::x86_64::CpuidResult;
use std::cmp::min;
use std::intrinsics::copy_nonoverlapping;
use std::mem::size_of;
use std::os::raw::c_int;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use base::errno_result;
use base::ioctl;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ptr_sized;
use base::ioctl_with_ref;
use base::warn;
use base::AsRawDescriptor;
use base::Error;
use base::RawDescriptor;
use base::Result;
use base::SafeDescriptor;
use data_model::vec_with_array_field;
use libc::EINVAL;
use libc::ENOENT;
use libc::ENXIO;
use libc::EOPNOTSUPP;
use vm_memory::GuestAddress;

use super::*;
use crate::get_tsc_offset_from_msr;
use crate::set_tsc_offset_via_msr;
use crate::CpuId;
use crate::CpuIdEntry;
use crate::DebugRegs;
use crate::DescriptorTable;
use crate::Fpu;
use crate::HypervHypercall;
use crate::IoOperation;
use crate::IoParams;
use crate::Register;
use crate::Regs;
use crate::Segment;
use crate::Sregs;
use crate::Vcpu;
use crate::VcpuExit;
use crate::VcpuRunHandle;
use crate::VcpuX86_64;
use crate::Xsave;

// HAXM exit reasons
// IO port request
const HAX_EXIT_IO: u32 = 1;
// MMIO instruction emulation, should not happen anymore, replaced with
// HAX_EXIT_FAST_MMIO
#[allow(dead_code)]
const HAX_EXIT_MMIO: u32 = 2;
// Real mode emulation when unrestricted guest is disabled
#[allow(dead_code)]
const HAX_EXIT_REALMODE: u32 = 3;
// Interrupt window open, crosvm can inject an interrupt now.
// Also used when vcpu thread receives a signal
const HAX_EXIT_INTERRUPT: u32 = 4;
// Unknown vmexit, mostly trigger reboot
const HAX_EXIT_UNKNOWN: u32 = 5;
// HALT from guest
const HAX_EXIT_HLT: u32 = 6;
// Reboot request, like because of triple fault in guest
const HAX_EXIT_STATECHANGE: u32 = 7;
// Paused by crosvm setting _exit_reason to HAX_EXIT_PAUSED before entry
pub(crate) const HAX_EXIT_PAUSED: u32 = 8;
// MMIO instruction emulation through io_buffer
const HAX_EXIT_FAST_MMIO: u32 = 9;
// Page fault that was not able to be handled by HAXM
const HAX_EXIT_PAGEFAULT: u32 = 10;
// A debug exception caused a vmexit
const HAX_EXIT_DEBUG: u32 = 11;

// HAXM exit directions
const HAX_EXIT_DIRECTION_PIO_IN: u32 = 1;
const HAX_EXIT_DIRECTION_PIO_OUT: u32 = 0;
const HAX_EXIT_DIRECTION_MMIO_READ: u8 = 0;
const HAX_EXIT_DIRECTION_MMIO_WRITE: u8 = 1;

pub struct HaxmVcpu {
    pub(super) descriptor: SafeDescriptor,
    pub(super) id: usize,
    pub(super) tunnel: *mut hax_tunnel,
    pub(super) io_buffer: *mut c_void,
    pub(super) vcpu_run_handle_fingerprint: Arc<AtomicU64>,
}

unsafe impl Send for HaxmVcpu {}
unsafe impl Sync for HaxmVcpu {}

impl AsRawDescriptor for HaxmVcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl HaxmVcpu {
    fn get_vcpu_state(&self) -> Result<VcpuState> {
        let mut state = vcpu_state_t::default();

        let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_GET_REGS(), &mut state) };
        if ret != 0 {
            return errno_result();
        }

        // Also read efer MSR
        let mut efer = vec![Register {
            id: IA32_EFER,
            value: 0,
        }];

        self.get_msrs(&mut efer)?;
        state._efer = efer[0].value as u32;

        Ok(VcpuState { state })
    }

    fn set_vcpu_state(&self, state: &mut VcpuState) -> Result<()> {
        let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_SET_REGS(), &mut state.state) };
        if ret != 0 {
            return errno_result();
        }

        // Also set efer MSR
        let efer = vec![Register {
            id: IA32_EFER,
            value: state.state._efer as u64,
        }];

        self.set_msrs(&efer)
    }
}

impl Vcpu for HaxmVcpu {
    /// Makes a shallow clone of this `Vcpu`.
    fn try_clone(&self) -> Result<Self> {
        Ok(HaxmVcpu {
            descriptor: self.descriptor.try_clone()?,
            id: self.id,
            tunnel: self.tunnel,
            io_buffer: self.io_buffer,
            vcpu_run_handle_fingerprint: self.vcpu_run_handle_fingerprint.clone(),
        })
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    fn take_run_handle(&self, signal_num: Option<c_int>) -> Result<VcpuRunHandle> {
        take_run_handle(self, signal_num)
    }

    /// Returns the vcpu id.
    fn id(&self) -> usize {
        self.id
    }

    /// Sets the bit that requests an immediate exit.
    fn set_immediate_exit(&self, exit: bool) {
        // Safe because we know the tunnel is a pointer to a hax_tunnel and we know its size.
        // Crosvm's HAXM implementation does not use the _exit_reason, so it's fine if we
        // overwrite it.
        unsafe {
            (*self.tunnel)._exit_reason = if exit { HAX_EXIT_PAUSED } else { 0 };
        }
    }

    /// Sets/clears the bit for immediate exit for the vcpu on the current thread.
    fn set_local_immediate_exit(exit: bool) {
        set_local_immediate_exit(exit)
    }

    fn set_local_immediate_exit_fn(&self) -> extern "C" fn() {
        extern "C" fn f() {
            HaxmVcpu::set_local_immediate_exit(true);
        }
        f
    }

    /// Signals to the hypervisor that this guest is being paused by userspace.  Only works on Vms
    /// that support `VmCapability::PvClockSuspend`.
    fn pvclock_ctrl(&self) -> Result<()> {
        Err(Error::new(libc::ENXIO))
        // HaxmVcpu does not support VmCapability::PvClockSuspend
    }

    /// Specifies set of signals that are blocked during execution of `RunnableVcpu::run`.  Signals
    /// that are not blocked will will cause run to return with `VcpuExit::Intr`. Only works on Vms
    /// that support `VmCapability::SignalMask`.
    fn set_signal_mask(&self, _signals: &[c_int]) -> Result<()> {
        // HaxmVcpu does not support VmCapability::SignalMask
        Err(Error::new(libc::ENXIO))
    }

    /// Enables a hypervisor-specific extension on this Vcpu.  `cap` is a constant defined by the
    /// hypervisor API.  `args` are the arguments for enabling the feature, if any.
    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        // Haxm does not support enable_capability
        Err(Error::new(libc::ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Mmio`.
    ///
    /// Once called, it will determine whether a mmio read or mmio write was the reason for the mmio exit,
    /// call `handle_fn` with the respective IoOperation to perform the mmio read or write,
    /// and set the return data in the vcpu so that the vcpu can resume running.
    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
        // kernel told us how large it was.
        // Verify that the handler is called for mmio context only.
        unsafe {
            assert!((*self.tunnel)._exit_status == HAX_EXIT_FAST_MMIO);
        }
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.
        let mmio = self.io_buffer as *mut hax_fastmmio;
        let (address, size, direction) =
            unsafe { ((*mmio).gpa, (*mmio).size as usize, (*mmio).direction) };

        match direction {
            HAX_EXIT_DIRECTION_MMIO_READ => {
                if let Some(data) = handle_fn(IoParams {
                    address,
                    size,
                    operation: IoOperation::Read,
                }) {
                    // Safe because we know this is an mmio read, so we need to put data into the
                    // "value" field of the hax_fastmmio.
                    let data = u64::from_ne_bytes(data);
                    unsafe {
                        (*mmio).__bindgen_anon_1.value = data;
                    }
                }
                Ok(())
            }
            HAX_EXIT_DIRECTION_MMIO_WRITE => {
                // safe because we trust haxm to fill in the union properly.
                let data = unsafe { (*mmio).__bindgen_anon_1.value };
                handle_fn(IoParams {
                    address,
                    size,
                    operation: IoOperation::Write {
                        data: data.to_ne_bytes(),
                    },
                });
                Ok(())
            }
            _ => Err(Error::new(EINVAL)),
        }
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Io`.
    ///
    /// Once called, it will determine whether an io in or io out was the reason for the io exit,
    /// call `handle_fn` with the respective IoOperation to perform the io in or io out,
    /// and set the return data in the vcpu so that the vcpu can resume running.
    #[allow(clippy::cast_ptr_alignment)]
    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
        // kernel told us how large it was.
        // Verify that the handler is called for io context only.
        unsafe {
            assert!((*self.tunnel)._exit_status == HAX_EXIT_IO);
        }
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.
        let io = unsafe { (*self.tunnel).__bindgen_anon_1.io };
        let address = io._port.into();
        let size = (io._count as usize) * (io._size as usize);
        match io._direction as u32 {
            HAX_EXIT_DIRECTION_PIO_IN => {
                if let Some(data) = handle_fn(IoParams {
                    address,
                    size,
                    operation: IoOperation::Read,
                }) {
                    // Safe because the exit_reason (which comes from the kernel) told us that
                    // this is port io, where the iobuf can be treated as a *u8
                    unsafe {
                        copy_nonoverlapping(data.as_ptr(), self.io_buffer as *mut u8, size);
                    }
                }
                Ok(())
            }
            HAX_EXIT_DIRECTION_PIO_OUT => {
                let mut data = [0; 8];
                // safe because we check the size, from what the kernel told us is the max to copy.
                unsafe {
                    copy_nonoverlapping(
                        self.io_buffer as *const u8,
                        data.as_mut_ptr(),
                        min(size, data.len()),
                    );
                }
                handle_fn(IoParams {
                    address,
                    size,
                    operation: IoOperation::Write { data },
                });
                Ok(())
            }
            _ => Err(Error::new(EINVAL)),
        }
    }

    /// haxm does not handle hypervcalls.
    fn handle_hyperv_hypercall(&self, _func: &mut dyn FnMut(HypervHypercall) -> u64) -> Result<()> {
        Err(Error::new(libc::ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::RdMsr`,
    /// and in the same thread as run.
    ///
    /// It will put `data` into the user buffer and return.
    fn handle_rdmsr(&self, _data: u64) -> Result<()> {
        // TODO(b/233766326): Implement.
        Err(Error::new(libc::ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::WrMsr`,
    /// and in the same thread as run.
    fn handle_wrmsr(&self) {
        // TODO(b/233766326): Implement.
    }

    #[allow(clippy::cast_ptr_alignment)]
    // The pointer is page aligned so casting to a different type is well defined, hence the clippy
    // allow attribute.
    fn run(&mut self, run_handle: &VcpuRunHandle) -> Result<VcpuExit> {
        // Acquire is used to ensure this check is ordered after the `compare_exchange` in `run`.
        if self
            .vcpu_run_handle_fingerprint
            .load(std::sync::atomic::Ordering::Acquire)
            != run_handle.fingerprint().as_u64()
        {
            panic!("invalid VcpuRunHandle used to run Vcpu");
        }

        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, HAX_VCPU_IOCTL_RUN()) };
        if ret != 0 {
            return errno_result();
        }

        // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
        // kernel told us how large it was.
        let exit_status = unsafe { (*self.tunnel)._exit_status };

        match exit_status {
            HAX_EXIT_IO => Ok(VcpuExit::Io),
            HAX_EXIT_INTERRUPT => Ok(VcpuExit::Intr),
            HAX_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
            HAX_EXIT_HLT => Ok(VcpuExit::Hlt),
            HAX_EXIT_STATECHANGE => Ok(VcpuExit::Shutdown),
            HAX_EXIT_FAST_MMIO => Ok(VcpuExit::Mmio),
            HAX_EXIT_PAGEFAULT => Ok(VcpuExit::Exception),
            HAX_EXIT_DEBUG => Ok(VcpuExit::Debug),
            HAX_EXIT_PAUSED => Ok(VcpuExit::Exception),
            r => panic!("unknown exit reason: {}", r),
        }
    }
}

impl VcpuX86_64 for HaxmVcpu {
    /// Sets or clears the flag that requests the VCPU to exit when it becomes possible to inject
    /// interrupts into the guest.
    fn set_interrupt_window_requested(&self, requested: bool) {
        // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
        // kernel told us how large it was.
        unsafe {
            (*self.tunnel).request_interrupt_window = i32::from(requested);
        }
    }

    /// Checks if we can inject an interrupt into the VCPU.
    fn ready_for_interrupt(&self) -> bool {
        // Safe because we know we mapped enough memory to hold the hax_tunnel struct because the
        // kernel told us how large it was.
        unsafe { (*self.tunnel).ready_for_interrupt_injection != 0 }
    }

    /// Injects interrupt vector `irq` into the VCPU.
    fn interrupt(&self, irq: u32) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, HAX_VCPU_IOCTL_INTERRUPT(), &irq) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Injects a non-maskable interrupt into the VCPU.
    fn inject_nmi(&self) -> Result<()> {
        warn!("HAXM does not support injecting NMIs");
        Ok(())
    }

    /// Gets the VCPU general purpose registers.
    fn get_regs(&self) -> Result<Regs> {
        Ok(self.get_vcpu_state()?.get_regs())
    }

    /// Sets the VCPU general purpose registers.
    fn set_regs(&self, regs: &Regs) -> Result<()> {
        let mut state = self.get_vcpu_state()?;
        state.set_regs(regs);
        self.set_vcpu_state(&mut state)?;
        Ok(())
    }

    /// Gets the VCPU special registers.
    fn get_sregs(&self) -> Result<Sregs> {
        Ok(self.get_vcpu_state()?.get_sregs())
    }

    /// Sets the VCPU special registers.
    fn set_sregs(&self, sregs: &Sregs) -> Result<()> {
        let mut state = self.get_vcpu_state()?;
        state.set_sregs(sregs);
        self.set_vcpu_state(&mut state)?;
        Ok(())
    }

    /// Gets the VCPU FPU registers.
    fn get_fpu(&self) -> Result<Fpu> {
        let mut fpu = fx_layout::default();
        let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_IOCTL_GET_FPU(), &mut fpu) };

        if ret != 0 {
            return errno_result();
        }

        Ok(Fpu::from(&fpu))
    }

    /// Sets the VCPU FPU registers.
    fn set_fpu(&self, fpu: &Fpu) -> Result<()> {
        let mut current_fpu = fx_layout::default();
        let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_IOCTL_GET_FPU(), &mut current_fpu) };

        if ret != 0 {
            return errno_result();
        }

        let mut new_fpu = fx_layout::from(fpu);

        // the mxcsr mask is something that isn't part of the Fpu state, so we make the new
        // fpu state's mxcsr_mask matches its current value
        new_fpu.mxcsr_mask = current_fpu.mxcsr_mask;

        let ret = unsafe { ioctl_with_ref(self, HAX_VCPU_IOCTL_SET_FPU(), &new_fpu) };

        if ret != 0 {
            return errno_result();
        }

        Ok(())
    }

    fn get_xsave(&self) -> Result<Xsave> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn set_xsave(&self, _xsave: &Xsave) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn get_interrupt_state(&self) -> Result<serde_json::Value> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn set_interrupt_state(&self, _data: serde_json::Value) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    /// Gets the VCPU debug registers.
    fn get_debugregs(&self) -> Result<DebugRegs> {
        Ok(self.get_vcpu_state()?.get_debugregs())
    }

    /// Sets the VCPU debug registers.
    fn set_debugregs(&self, debugregs: &DebugRegs) -> Result<()> {
        let mut state = self.get_vcpu_state()?;
        state.set_debugregs(debugregs);
        self.set_vcpu_state(&mut state)?;
        Ok(())
    }

    /// Gets the VCPU extended control registers.
    fn get_xcrs(&self) -> Result<Vec<Register>> {
        // Haxm does not support setting XCRs
        Err(Error::new(libc::ENXIO))
    }

    /// Sets the VCPU extended control registers.
    fn set_xcrs(&self, _xcrs: &[Register]) -> Result<()> {
        // Haxm does not support setting XCRs
        Err(Error::new(libc::ENXIO))
    }

    /// Gets the model-specific registers.  `msrs` specifies the MSR indexes to be queried, and
    /// on success contains their indexes and values.
    fn get_msrs(&self, msrs: &mut Vec<Register>) -> Result<()> {
        // HAX_VCPU_IOCTL_GET_MSRS only allows you to set HAX_MAX_MSR_ARRAY-1 msrs at a time
        // TODO (b/163811378): the fact that you can only set HAX_MAX_MSR_ARRAY-1 seems like a
        // bug with HAXM, since the entries array itself is HAX_MAX_MSR_ARRAY long
        for chunk in msrs.chunks_mut((HAX_MAX_MSR_ARRAY - 1) as usize) {
            let chunk_size = chunk.len();
            let hax_chunk: Vec<vmx_msr> = chunk.iter().map(vmx_msr::from).collect();

            let mut msr_data = hax_msr_data {
                nr_msr: chunk_size as u16,
                ..Default::default()
            };

            // Copy chunk into msr_data
            msr_data.entries[..chunk_size].copy_from_slice(&hax_chunk);

            let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_IOCTL_GET_MSRS(), &mut msr_data) };
            if ret != 0 {
                return errno_result();
            }

            // copy values we got from kernel
            for (i, item) in chunk.iter_mut().enumerate().take(chunk_size) {
                item.value = msr_data.entries[i].value;
            }
        }

        Ok(())
    }

    fn get_all_msrs(&self) -> Result<Vec<Register>> {
        Err(Error::new(EOPNOTSUPP))
    }

    /// Sets the model-specific registers.
    fn set_msrs(&self, msrs: &[Register]) -> Result<()> {
        // HAX_VCPU_IOCTL_GET_MSRS only allows you to set HAX_MAX_MSR_ARRAY-1 msrs at a time
        // TODO (b/163811378): the fact that you can only set HAX_MAX_MSR_ARRAY-1 seems like a
        // bug with HAXM, since the entries array itself is HAX_MAX_MSR_ARRAY long
        for chunk in msrs.chunks((HAX_MAX_MSR_ARRAY - 1) as usize) {
            let chunk_size = chunk.len();
            let hax_chunk: Vec<vmx_msr> = chunk.iter().map(vmx_msr::from).collect();

            let mut msr_data = hax_msr_data {
                nr_msr: chunk_size as u16,
                ..Default::default()
            };

            // Copy chunk into msr_data
            msr_data.entries[..chunk_size].copy_from_slice(&hax_chunk);

            let ret = unsafe { ioctl_with_mut_ref(self, HAX_VCPU_IOCTL_SET_MSRS(), &mut msr_data) };
            if ret != 0 {
                return errno_result();
            }
        }

        Ok(())
    }

    /// Sets up the data returned by the CPUID instruction.
    fn set_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        let total = cpuid.cpu_id_entries.len();
        let mut hax = vec_with_array_field::<hax_cpuid, hax_cpuid_entry>(total);
        hax[0].total = total as u32;
        let entries = unsafe { hax[0].entries.as_mut_slice(total) };
        for (i, e) in cpuid.cpu_id_entries.iter().enumerate() {
            entries[i] = hax_cpuid_entry::from(e);
        }

        let ret = unsafe {
            ioctl_with_ptr_sized(
                self,
                HAX_VCPU_IOCTL_SET_CPUID(),
                hax.as_ptr(),
                size_of::<hax_cpuid>() + total * size_of::<hax_cpuid_entry>(),
            )
        };

        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Cpuid`, and `entry`
    /// should represent the result of emulating the CPUID instruction. The `handle_cpuid` function
    /// will then set the appropriate registers on the vcpu.
    /// HAXM does not support the VcpuExit::Cpuid exit type.
    fn handle_cpuid(&mut self, _entry: &CpuIdEntry) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    /// Gets the system emulated hyper-v CPUID values.
    fn get_hyperv_cpuid(&self) -> Result<CpuId> {
        // HaxmVcpu does not support hyperv_cpuid
        Err(Error::new(libc::ENXIO))
    }

    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        // TODO(b/173807302): Implement this
        Err(Error::new(ENOENT))
    }

    fn get_tsc_offset(&self) -> Result<u64> {
        // Use the default MSR-based implementation
        get_tsc_offset_from_msr(self)
    }

    fn set_tsc_offset(&self, offset: u64) -> Result<()> {
        // Use the default MSR-based implementation
        set_tsc_offset_via_msr(self, offset)
    }
}

struct VcpuState {
    state: vcpu_state_t,
}

impl VcpuState {
    fn get_regs(&self) -> Regs {
        unsafe {
            Regs {
                rax: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    ._rax,
                rbx: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_4
                    ._rbx,
                rcx: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_2
                    ._rcx,
                rdx: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_3
                    ._rdx,
                rsi: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_7
                    ._rsi,
                rdi: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_8
                    ._rdi,
                rsp: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_5
                    ._rsp,
                rbp: self
                    .state
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .__bindgen_anon_6
                    ._rbp,
                r8: self.state.__bindgen_anon_1.__bindgen_anon_1._r8,
                r9: self.state.__bindgen_anon_1.__bindgen_anon_1._r9,
                r10: self.state.__bindgen_anon_1.__bindgen_anon_1._r10,
                r11: self.state.__bindgen_anon_1.__bindgen_anon_1._r11,
                r12: self.state.__bindgen_anon_1.__bindgen_anon_1._r12,
                r13: self.state.__bindgen_anon_1.__bindgen_anon_1._r13,
                r14: self.state.__bindgen_anon_1.__bindgen_anon_1._r14,
                r15: self.state.__bindgen_anon_1.__bindgen_anon_1._r15,
                rip: self.state.__bindgen_anon_2._rip,
                rflags: self.state.__bindgen_anon_3._rflags,
            }
        }
    }

    fn set_regs(&mut self, regs: &Regs) {
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_1
            ._rax = regs.rax;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_4
            ._rbx = regs.rbx;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_2
            ._rcx = regs.rcx;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_3
            ._rdx = regs.rdx;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_7
            ._rsi = regs.rsi;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_8
            ._rdi = regs.rdi;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_5
            ._rsp = regs.rsp;
        self.state
            .__bindgen_anon_1
            .__bindgen_anon_1
            .__bindgen_anon_6
            ._rbp = regs.rbp;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r8 = regs.r8;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r9 = regs.r9;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r10 = regs.r10;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r11 = regs.r11;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r12 = regs.r12;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r13 = regs.r13;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r14 = regs.r14;
        self.state.__bindgen_anon_1.__bindgen_anon_1._r15 = regs.r15;
        self.state.__bindgen_anon_2._rip = regs.rip;
        self.state.__bindgen_anon_3._rflags = regs.rflags;
    }

    fn get_sregs(&self) -> Sregs {
        Sregs {
            cs: Segment::from(&self.state._cs),
            ds: Segment::from(&self.state._ds),
            es: Segment::from(&self.state._es),
            fs: Segment::from(&self.state._fs),
            gs: Segment::from(&self.state._gs),
            ss: Segment::from(&self.state._ss),
            tr: Segment::from(&self.state._tr),
            ldt: Segment::from(&self.state._ldt),
            gdt: DescriptorTable::from(&self.state._gdt),
            idt: DescriptorTable::from(&self.state._idt),
            cr0: self.state._cr0,
            cr2: self.state._cr2,
            cr3: self.state._cr3,
            cr4: self.state._cr4,
            // HAXM does not support setting cr8
            cr8: 0,
            efer: self.state._efer as u64,
        }
    }

    fn set_sregs(&mut self, sregs: &Sregs) {
        self.state._cs = segment_desc_t::from(&sregs.cs);
        self.state._ds = segment_desc_t::from(&sregs.ds);
        self.state._es = segment_desc_t::from(&sregs.es);
        self.state._fs = segment_desc_t::from(&sregs.fs);
        self.state._gs = segment_desc_t::from(&sregs.gs);
        self.state._ss = segment_desc_t::from(&sregs.ss);
        self.state._tr = segment_desc_t::from(&sregs.tr);
        self.state._ldt = segment_desc_t::from(&sregs.ldt);
        self.state._gdt = segment_desc_t::from(&sregs.gdt);
        self.state._idt = segment_desc_t::from(&sregs.idt);
        self.state._cr0 = sregs.cr0;
        self.state._cr2 = sregs.cr2;
        self.state._cr3 = sregs.cr3;
        self.state._cr4 = sregs.cr4;
        self.state._efer = sregs.efer as u32;
    }

    fn get_debugregs(&self) -> DebugRegs {
        DebugRegs {
            db: [
                self.state._dr0,
                self.state._dr1,
                self.state._dr2,
                self.state._dr3,
            ],
            dr6: self.state._dr6,
            dr7: self.state._dr7,
        }
    }

    fn set_debugregs(&mut self, debugregs: &DebugRegs) {
        self.state._dr0 = debugregs.db[0];
        self.state._dr1 = debugregs.db[1];
        self.state._dr2 = debugregs.db[2];
        self.state._dr3 = debugregs.db[3];
        self.state._dr6 = debugregs.dr6;
        self.state._dr7 = debugregs.dr7;
    }
}

// HAXM's segment descriptor format matches exactly with the VMCS structure. The format
// of the AR bits is described in the Intel System Programming Guide Part 3, chapter 24.4.1,
// table 24-2. The main confusing thing is that the type_ field in haxm is 4 bits, meaning
// the 3 least significant bits represent the normal type field, and the most significant
// bit represents the "descriptor type" field.

impl From<&segment_desc_t> for Segment {
    fn from(item: &segment_desc_t) -> Self {
        unsafe {
            Segment {
                base: item.base,
                limit: item.limit,
                selector: item.selector,
                type_: item.__bindgen_anon_1.__bindgen_anon_1.type_() as u8,
                present: item.__bindgen_anon_1.__bindgen_anon_1.present() as u8,
                dpl: item.__bindgen_anon_1.__bindgen_anon_1.dpl() as u8,
                db: item.__bindgen_anon_1.__bindgen_anon_1.operand_size() as u8,
                s: item.__bindgen_anon_1.__bindgen_anon_1.desc() as u8,
                l: item.__bindgen_anon_1.__bindgen_anon_1.long_mode() as u8,
                g: item.__bindgen_anon_1.__bindgen_anon_1.granularity() as u8,
                avl: item.__bindgen_anon_1.__bindgen_anon_1.available() as u8,
            }
        }
    }
}

impl From<&Segment> for segment_desc_t {
    fn from(item: &Segment) -> Self {
        let mut segment = segment_desc_t {
            base: item.base,
            limit: item.limit,
            selector: item.selector,
            ..Default::default()
        };

        unsafe {
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_type(item.type_ as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_desc(item.s as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_present(item.present as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_dpl(item.dpl as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_operand_size(item.db as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_long_mode(item.l as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_granularity(item.g as u32);
            segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_available(item.avl as u32);
        }

        segment
    }
}

impl From<&segment_desc_t> for DescriptorTable {
    fn from(item: &segment_desc_t) -> Self {
        DescriptorTable {
            base: item.base,
            limit: item.limit as u16,
        }
    }
}

impl From<&DescriptorTable> for segment_desc_t {
    fn from(item: &DescriptorTable) -> Self {
        segment_desc_t {
            base: item.base,
            limit: item.limit as u32,
            ..Default::default()
        }
    }
}

impl From<&fx_layout> for Fpu {
    fn from(item: &fx_layout) -> Self {
        let mut fpu = Fpu {
            fpr: item.st_mm,
            fcw: item.fcw,
            fsw: item.fsw,
            ftwx: item.ftw,
            last_opcode: item.fop,
            last_ip: unsafe { item.__bindgen_anon_1.fpu_ip },
            last_dp: unsafe { item.__bindgen_anon_2.fpu_dp },
            xmm: [[0; 16]; 16],
            mxcsr: item.mxcsr,
        };

        fpu.xmm[..8].copy_from_slice(&item.mmx_1[..]);
        fpu.xmm[8..].copy_from_slice(&item.mmx_2[..]);

        fpu
    }
}

impl From<&Fpu> for fx_layout {
    fn from(item: &Fpu) -> Self {
        let mut fpu = fx_layout {
            fcw: item.fcw,
            fsw: item.fsw,
            ftw: item.ftwx,
            res1: 0,
            fop: item.last_opcode,
            __bindgen_anon_1: fx_layout__bindgen_ty_1 {
                fpu_ip: item.last_ip,
            },
            __bindgen_anon_2: fx_layout__bindgen_ty_2 {
                fpu_dp: item.last_dp,
            },
            mxcsr: item.mxcsr,
            mxcsr_mask: 0,
            st_mm: item.fpr,
            mmx_1: [[0; 16]; 8],
            mmx_2: [[0; 16]; 8],
            pad: [0; 96],
        };

        fpu.mmx_1.copy_from_slice(&item.xmm[..8]);
        fpu.mmx_2.copy_from_slice(&item.xmm[8..]);

        fpu
    }
}

impl From<&hax_cpuid_entry> for CpuIdEntry {
    fn from(item: &hax_cpuid_entry) -> Self {
        CpuIdEntry {
            function: item.function,
            index: item.index,
            flags: item.flags,
            cpuid: CpuidResult {
                eax: item.eax,
                ebx: item.ebx,
                ecx: item.ecx,
                edx: item.edx,
            },
        }
    }
}

impl From<&CpuIdEntry> for hax_cpuid_entry {
    fn from(item: &CpuIdEntry) -> Self {
        hax_cpuid_entry {
            function: item.function,
            index: item.index,
            flags: item.flags,
            eax: item.cpuid.eax,
            ebx: item.cpuid.ebx,
            ecx: item.cpuid.ecx,
            edx: item.cpuid.edx,
            pad: Default::default(),
        }
    }
}

impl From<&vmx_msr> for Register {
    fn from(item: &vmx_msr) -> Register {
        Register {
            id: item.entry as u32,
            value: item.value,
        }
    }
}

impl From<&Register> for vmx_msr {
    fn from(item: &Register) -> vmx_msr {
        vmx_msr {
            entry: item.id as u64,
            value: item.value,
        }
    }
}

// TODO(b:241252288): Enable tests disabled with dummy feature flag - enable_haxm_tests.
#[cfg(test)]
#[cfg(feature = "enable_haxm_tests")]
mod tests {
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use super::*;
    use crate::VmX86_64;

    // EFER Bits
    const EFER_SCE: u64 = 0x00000001;
    const EFER_LME: u64 = 0x00000100;
    const EFER_LMA: u64 = 0x00000400;

    // CR0 bits
    const CR0_PG: u64 = 1 << 31;

    #[test]
    fn get_regs() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        vcpu.get_regs().expect("failed to get regs");
    }

    #[test]
    fn get_fpu() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        vcpu.get_fpu().expect("failed to get fpu");
    }

    #[test]
    fn set_many_msrs() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut registers: Vec<Register> = Vec::new();
        for id in 0x300..0x3ff {
            registers.push(Register {
                id: 38,
                value: id as u64,
            });
        }

        vcpu.set_msrs(&registers).expect("failed to set registers");
    }

    #[test]
    fn get_many_msrs() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut registers: Vec<Register> = Vec::new();
        for id in 0x300..0x3ff {
            registers.push(Register {
                id: 38,
                value: id as u64,
            });
        }

        vcpu.get_msrs(&mut registers)
            .expect("failed to get registers");
    }

    #[test]
    fn set_cpuid() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut cpuid = haxm
            .get_supported_cpuid()
            .expect("failed to get supported cpuids");
        for entry in &mut cpuid.cpu_id_entries {
            if entry.function == 1 {
                // Disable XSAVE and OSXSAVE
                entry.cpuid.ecx &= !(1 << 26);
                entry.cpuid.ecx &= !(1 << 27);
            }
        }

        vcpu.set_cpuid(&cpuid).expect("failed to set cpuid");
    }

    #[test]
    fn set_efer() {
        // HAXM efer setting requires some extra code, so we have this test specifically
        // checking that it's working.
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = HaxmVm::new(&haxm, mem).expect("failed to create vm");
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut sregs = vcpu.get_sregs().expect("failed to get sregs");
        // Initial value should be 0
        assert_eq!(sregs.efer, 0);

        // Enable and activate long mode
        sregs.efer = EFER_LMA | EFER_LME;
        // Need to enable paging or LMA will be turned off
        sregs.cr0 |= CR0_PG;
        vcpu.set_sregs(&sregs).expect("failed to set sregs");

        // Verify that setting stuck
        let sregs = vcpu.get_sregs().expect("failed to get sregs");
        assert_eq!(sregs.efer, EFER_LMA | EFER_LME);

        // IA32_EFER register value should match
        let mut efer_reg = vec![Register {
            id: IA32_EFER,
            value: 0,
        }];
        vcpu.get_msrs(&mut efer_reg).expect("failed to get msrs");
        assert_eq!(efer_reg[0].value, EFER_LMA | EFER_LME);

        // Enable SCE via set_msrs
        efer_reg[0].value |= EFER_SCE;
        vcpu.set_msrs(&efer_reg).expect("failed to set msrs");

        // Verify that setting stuck
        let sregs = vcpu.get_sregs().expect("failed to get sregs");
        assert_eq!(sregs.efer, EFER_SCE | EFER_LME | EFER_LMA);
        vcpu.get_msrs(&mut efer_reg).expect("failed to get msrs");
        assert_eq!(efer_reg[0].value, EFER_SCE | EFER_LME | EFER_LMA);
    }
}
