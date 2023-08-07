// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::ffi::c_void;
use std::arch::x86_64::CpuidResult;
use std::convert::TryInto;
use std::mem::size_of;
use std::sync::Arc;

use base::Error;
use base::Result;
use libc::EINVAL;
use libc::EIO;
use libc::ENOENT;
use libc::ENXIO;
use vm_memory::GuestAddress;
use winapi::shared::winerror::E_UNEXPECTED;
use windows::Win32::Foundation::WHV_E_INSUFFICIENT_BUFFER;

use super::types::*;
use super::*;
use crate::get_tsc_offset_from_msr;
use crate::set_tsc_offset_via_msr;
use crate::CpuId;
use crate::CpuIdEntry;
use crate::DebugRegs;
use crate::Fpu;
use crate::HypervHypercall;
use crate::IoOperation;
use crate::IoParams;
use crate::Register;
use crate::Regs;
use crate::Sregs;
use crate::Vcpu;
use crate::VcpuExit;
use crate::VcpuX86_64;
use crate::Xsave;

const WHPX_EXIT_DIRECTION_MMIO_READ: u8 = 0;
const WHPX_EXIT_DIRECTION_MMIO_WRITE: u8 = 1;
const WHPX_EXIT_DIRECTION_PIO_IN: u8 = 0;
const WHPX_EXIT_DIRECTION_PIO_OUT: u8 = 1;

/// This is the whpx instruction emulator, useful for deconstructing
/// io & memory port instructions. Whpx does not do this automatically.
struct SafeInstructionEmulator {
    handle: WHV_EMULATOR_HANDLE,
}

impl SafeInstructionEmulator {
    fn new() -> Result<SafeInstructionEmulator> {
        const EMULATOR_CALLBACKS: WHV_EMULATOR_CALLBACKS = WHV_EMULATOR_CALLBACKS {
            Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(SafeInstructionEmulator::io_port_cb),
            WHvEmulatorMemoryCallback: Some(SafeInstructionEmulator::memory_cb),
            WHvEmulatorGetVirtualProcessorRegisters: Some(
                SafeInstructionEmulator::get_virtual_processor_registers_cb,
            ),
            WHvEmulatorSetVirtualProcessorRegisters: Some(
                SafeInstructionEmulator::set_virtual_processor_registers_cb,
            ),
            WHvEmulatorTranslateGvaPage: Some(SafeInstructionEmulator::translate_gva_page_cb),
        };
        let mut handle: WHV_EMULATOR_HANDLE = std::ptr::null_mut();
        // safe because pass in valid callbacks and a emulator handle for the kernel to place the allocated handle into.
        check_whpx!(unsafe { WHvEmulatorCreateEmulator(&EMULATOR_CALLBACKS, &mut handle) })?;

        Ok(SafeInstructionEmulator { handle })
    }
}

trait InstructionEmulatorCallbacks {
    extern "stdcall" fn io_port_cb(
        context: *mut ::std::os::raw::c_void,
        io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT;
    extern "stdcall" fn memory_cb(
        context: *mut ::std::os::raw::c_void,
        memory_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT;
    extern "stdcall" fn get_virtual_processor_registers_cb(
        context: *mut ::std::os::raw::c_void,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *mut WHV_REGISTER_VALUE,
    ) -> HRESULT;
    extern "stdcall" fn set_virtual_processor_registers_cb(
        context: *mut ::std::os::raw::c_void,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *const WHV_REGISTER_VALUE,
    ) -> HRESULT;
    extern "stdcall" fn translate_gva_page_cb(
        context: *mut ::std::os::raw::c_void,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: *mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT;
}

/// Context passed into the instruction emulator when trying io or mmio emulation.
/// Since we need this for set/get registers and memory translation,
/// a single context is used that captures all necessary contextual information for the operation.
struct InstructionEmulatorContext<'a> {
    vm_partition: Arc<SafePartition>,
    index: u32,
    handle_mmio: Option<&'a mut dyn FnMut(IoParams) -> Option<[u8; 8]>>,
    handle_io: Option<&'a mut dyn FnMut(IoParams) -> Option<[u8; 8]>>,
}

impl InstructionEmulatorCallbacks for SafeInstructionEmulator {
    extern "stdcall" fn io_port_cb(
        context: *mut ::std::os::raw::c_void,
        io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {
        // unsafe because windows could decide to call this at any time.
        // However, we trust the kernel to call this while the vm/vcpu is valid.
        let ctx = unsafe { &mut *(context as *mut InstructionEmulatorContext) };
        // safe because we trust the kernel to fill in the io_access
        let io_access_info = unsafe { &mut *io_access };
        let address = io_access_info.Port.into();
        let size = io_access_info.AccessSize as usize;
        match io_access_info.Direction {
            WHPX_EXIT_DIRECTION_PIO_IN => {
                if let Some(handle_io) = &mut ctx.handle_io {
                    if let Some(data) = handle_io(IoParams {
                        address,
                        size,
                        operation: IoOperation::Read,
                    }) {
                        // Safe because we know this is an io_access_info field of u32,
                        //  so casting as a &mut [u8] of len 4 is safe.
                        let buffer = unsafe {
                            std::slice::from_raw_parts_mut(
                                &mut io_access_info.Data as *mut u32 as *mut u8,
                                4,
                            )
                        };
                        buffer[..size].copy_from_slice(&data[..size]);
                    }
                    S_OK
                } else {
                    E_UNEXPECTED
                }
            }
            WHPX_EXIT_DIRECTION_PIO_OUT => {
                if let Some(handle_io) = &mut ctx.handle_io {
                    handle_io(IoParams {
                        address,
                        size,
                        operation: IoOperation::Write {
                            data: (io_access_info.Data as u64).to_ne_bytes(),
                        },
                    });
                    S_OK
                } else {
                    E_UNEXPECTED
                }
            }
            _ => E_UNEXPECTED,
        }
    }
    extern "stdcall" fn memory_cb(
        context: *mut ::std::os::raw::c_void,
        memory_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {
        // unsafe because windows could decide to call this at any time.
        // However, we trust the kernel to call this while the vm/vcpu is valid.
        let ctx = unsafe { &mut *(context as *mut InstructionEmulatorContext) };
        // safe because we trust the kernel to fill in the memory_access
        let memory_access_info = unsafe { &mut *memory_access };
        let address = memory_access_info.GpaAddress;
        let size = memory_access_info.AccessSize as usize;
        match memory_access_info.Direction {
            WHPX_EXIT_DIRECTION_MMIO_READ => {
                if let Some(handle_mmio) = &mut ctx.handle_mmio {
                    if let Some(data) = handle_mmio(IoParams {
                        address,
                        size,
                        operation: IoOperation::Read,
                    }) {
                        memory_access_info.Data = data;
                    }
                    S_OK
                } else {
                    E_UNEXPECTED
                }
            }
            WHPX_EXIT_DIRECTION_MMIO_WRITE => {
                if let Some(handle_mmio) = &mut ctx.handle_mmio {
                    handle_mmio(IoParams {
                        address,
                        size,
                        operation: IoOperation::Write {
                            data: memory_access_info.Data,
                        },
                    });
                    S_OK
                } else {
                    E_UNEXPECTED
                }
            }
            _ => E_UNEXPECTED,
        }
    }
    extern "stdcall" fn get_virtual_processor_registers_cb(
        context: *mut ::std::os::raw::c_void,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *mut WHV_REGISTER_VALUE,
    ) -> HRESULT {
        // unsafe because windows could decide to call this at any time.
        // However, we trust the kernel to call this while the vm/vcpu is valid.
        let ctx = unsafe { &*(context as *const InstructionEmulatorContext) };
        // safe because the ctx has a weak reference to the vm partition, which should be
        // alive longer than the ctx
        unsafe {
            WHvGetVirtualProcessorRegisters(
                ctx.vm_partition.partition,
                ctx.index,
                register_names,
                register_count,
                register_values,
            )
        }
    }
    extern "stdcall" fn set_virtual_processor_registers_cb(
        context: *mut ::std::os::raw::c_void,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *const WHV_REGISTER_VALUE,
    ) -> HRESULT {
        // unsafe because windows could decide to call this at any time.
        // However, we trust the kernel to call this while the vm/vcpu is valid.
        let ctx = unsafe { &*(context as *const InstructionEmulatorContext) };
        // safe because the ctx has a weak reference to the vm partition, which should be
        // alive longer than the ctx
        unsafe {
            WHvSetVirtualProcessorRegisters(
                ctx.vm_partition.partition,
                ctx.index,
                register_names,
                register_count,
                register_values,
            )
        }
    }
    extern "stdcall" fn translate_gva_page_cb(
        context: *mut ::std::os::raw::c_void,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result_code: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: *mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        // unsafe because windows could decide to call this at any time.
        // However, we trust the kernel to call this while the vm/vcpu is valid.
        let ctx = unsafe { &*(context as *const InstructionEmulatorContext) };
        let mut translation_result: WHV_TRANSLATE_GVA_RESULT = Default::default();
        // safe because the ctx has a weak reference to the vm partition, which should be
        // alive longer than the ctx
        let ret = unsafe {
            WHvTranslateGva(
                ctx.vm_partition.partition,
                ctx.index,
                gva,
                translate_flags,
                &mut translation_result,
                gpa,
            )
        };
        if ret == S_OK {
            // safe assuming the kernel passed in a valid result_code ptr
            unsafe {
                *translation_result_code = translation_result.ResultCode;
            }
        }
        ret
    }
}

impl Drop for SafeInstructionEmulator {
    fn drop(&mut self) {
        // safe because we own the instruction emulator
        check_whpx!(unsafe { WHvEmulatorDestroyEmulator(self.handle) }).unwrap();
    }
}

// we can send and share the instruction emulator over threads safely even though it is void*.
unsafe impl Send for SafeInstructionEmulator {}
unsafe impl Sync for SafeInstructionEmulator {}

struct SafeVirtualProcessor {
    vm_partition: Arc<SafePartition>,
    index: u32,
}

impl SafeVirtualProcessor {
    fn new(vm_partition: Arc<SafePartition>, index: u32) -> Result<SafeVirtualProcessor> {
        // safe since the vm partition should be valid.
        check_whpx!(unsafe { WHvCreateVirtualProcessor(vm_partition.partition, index, 0) })?;
        Ok(SafeVirtualProcessor {
            vm_partition,
            index,
        })
    }
}

impl Drop for SafeVirtualProcessor {
    fn drop(&mut self) {
        // safe because we are the owner of this windows virtual processor.
        check_whpx!(unsafe { WHvDeleteVirtualProcessor(self.vm_partition.partition, self.index,) })
            .unwrap();
    }
}

pub struct WhpxVcpu {
    index: u32,
    safe_virtual_processor: Arc<SafeVirtualProcessor>,
    vm_partition: Arc<SafePartition>,
    last_exit_context: Arc<WHV_RUN_VP_EXIT_CONTEXT>,
    // must be arc, since we cannot "dupe" an instruction emulator similar to a handle.
    instruction_emulator: Arc<SafeInstructionEmulator>,
    tsc_frequency: Option<u64>,
    apic_frequency: Option<u32>,
}

impl WhpxVcpu {
    /// The SafePartition passed in is weak, so that there is no circular references.
    /// However, the SafePartition should be valid as long as this VCPU is alive. The index
    /// is the index for this vcpu.
    pub(super) fn new(vm_partition: Arc<SafePartition>, index: u32) -> Result<WhpxVcpu> {
        let safe_virtual_processor = SafeVirtualProcessor::new(vm_partition.clone(), index)?;
        let instruction_emulator = SafeInstructionEmulator::new()?;
        Ok(WhpxVcpu {
            index,
            safe_virtual_processor: Arc::new(safe_virtual_processor),
            vm_partition,
            last_exit_context: Arc::new(Default::default()),
            instruction_emulator: Arc::new(instruction_emulator),
            tsc_frequency: None,
            apic_frequency: None,
        })
    }

    pub fn set_frequencies(&mut self, tsc_frequency: Option<u64>, lapic_frequency: u32) {
        self.tsc_frequency = tsc_frequency;
        self.apic_frequency = Some(lapic_frequency);
    }

    /// Handle reading the MSR with id `id`. If MSR `id` is not supported, inject a GP fault.
    fn handle_msr_read(&mut self, id: u32) -> Result<()> {
        // Verify that we're only being called in a situation where the last exit reason was
        // ExitReasonX64MsrAccess
        if self.last_exit_context.ExitReason
            != WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess
        {
            return Err(Error::new(EINVAL));
        }

        let value = match id {
            HV_X64_MSR_TSC_FREQUENCY => Some(self.tsc_frequency.unwrap_or(0)),
            HV_X64_MSR_APIC_FREQUENCY => Some(self.apic_frequency.unwrap_or(0) as u64),
            _ => None,
        };

        if let Some(value) = value {
            // Get the next rip from the exit context
            let rip = self.last_exit_context.VpContext.Rip
                + self.last_exit_context.VpContext.InstructionLength() as u64;

            const REG_NAMES: [WHV_REGISTER_NAME; 3] = [
                WHV_REGISTER_NAME_WHvX64RegisterRip,
                WHV_REGISTER_NAME_WHvX64RegisterRax,
                WHV_REGISTER_NAME_WHvX64RegisterRdx,
            ];

            let values = vec![
                WHV_REGISTER_VALUE { Reg64: rip },
                // RDMSR instruction puts lower 32 bits in EAX and upper 32 bits in EDX
                WHV_REGISTER_VALUE {
                    Reg64: (value & 0xffffffff),
                },
                WHV_REGISTER_VALUE {
                    Reg64: (value >> 32),
                },
            ];

            // safe because we have enough space for all the registers
            check_whpx!(unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.vm_partition.partition,
                    self.index,
                    &REG_NAMES as *const WHV_REGISTER_NAME,
                    REG_NAMES.len() as u32,
                    values.as_ptr() as *const WHV_REGISTER_VALUE,
                )
            })
        } else {
            self.inject_gp_fault()
        }
    }

    /// Handle writing the MSR with id `id`. If MSR `id` is not supported, inject a GP fault.
    fn handle_msr_write(&mut self, id: u32, _value: u64) -> Result<()> {
        // Verify that we're only being called in a situation where the last exit reason was
        // ExitReasonX64MsrAccess
        if self.last_exit_context.ExitReason
            != WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess
        {
            return Err(Error::new(EINVAL));
        }

        // Do nothing, we assume TSC is always invariant
        let success = matches!(id, HV_X64_MSR_TSC_INVARIANT_CONTROL);

        if !success {
            return self.inject_gp_fault();
        }

        // Get the next rip from the exit context
        let rip = self.last_exit_context.VpContext.Rip
            + self.last_exit_context.VpContext.InstructionLength() as u64;

        const REG_NAMES: [WHV_REGISTER_NAME; 1] = [WHV_REGISTER_NAME_WHvX64RegisterRip];

        let values = vec![WHV_REGISTER_VALUE { Reg64: rip }];

        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE,
            )
        })
    }

    fn inject_gp_fault(&self) -> Result<()> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] = [WHV_REGISTER_NAME_WHvRegisterPendingEvent];

        let mut event = WHV_REGISTER_VALUE {
            ExceptionEvent: WHV_X64_PENDING_EXCEPTION_EVENT {
                __bindgen_anon_1: Default::default(),
            },
        };
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                &mut event as *mut WHV_REGISTER_VALUE,
            )
        })?;

        if unsafe { event.ExceptionEvent.__bindgen_anon_1.EventPending() } != 0 {
            error!("Unable to inject gp fault because pending exception exists");
            return Err(Error::new(EINVAL));
        }

        let mut pending_exception = unsafe { event.ExceptionEvent.__bindgen_anon_1 };

        pending_exception.set_EventPending(1);
        // GP faults set error code
        pending_exception.set_DeliverErrorCode(1);
        // GP fault error code is 0 unless the fault is segment related
        pending_exception.ErrorCode = 0;
        // This must be set to WHvX64PendingEventException
        pending_exception
            .set_EventType(WHV_X64_PENDING_EVENT_TYPE_WHvX64PendingEventException as u32);
        // GP fault vector is 13
        const GP_VECTOR: u32 = 13;
        pending_exception.set_Vector(GP_VECTOR);

        let event = WHV_REGISTER_VALUE {
            ExceptionEvent: WHV_X64_PENDING_EXCEPTION_EVENT {
                __bindgen_anon_1: pending_exception,
            },
        };

        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                &event as *const WHV_REGISTER_VALUE,
            )
        })
    }
}

impl Vcpu for WhpxVcpu {
    /// Makes a shallow clone of this `Vcpu`.
    fn try_clone(&self) -> Result<Self> {
        Ok(WhpxVcpu {
            index: self.index,
            safe_virtual_processor: self.safe_virtual_processor.clone(),
            vm_partition: self.vm_partition.clone(),
            last_exit_context: self.last_exit_context.clone(),
            instruction_emulator: self.instruction_emulator.clone(),
            tsc_frequency: self.tsc_frequency,
            apic_frequency: self.apic_frequency,
        })
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    /// Returns the vcpu id.
    fn id(&self) -> usize {
        self.index.try_into().unwrap()
    }

    /// Exits the vcpu immediately if exit is true
    fn set_immediate_exit(&self, exit: bool) {
        if exit {
            // safe because we own this whpx virtual processor index, and assume the vm partition is still valid
            unsafe {
                WHvCancelRunVirtualProcessor(self.vm_partition.partition, self.index, 0);
            }
        }
    }

    /// Signals to the hypervisor that this guest is being paused by userspace. On some hypervisors,
    /// this is used to control the pvclock. On WHPX, we handle it separately with virtio-pvclock.
    /// So the correct implementation here is to do nothing.
    fn on_suspend(&self) -> Result<()> {
        Ok(())
    }

    /// Enables a hypervisor-specific extension on this Vcpu.  `cap` is a constant defined by the
    /// hypervisor API (e.g., kvm.h).  `args` are the arguments for enabling the feature, if any.
    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        // Whpx does not support raw capability on the vcpu.
        Err(Error::new(ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Mmio`.
    ///
    /// Once called, it will determine whether a mmio read or mmio write was the reason for the mmio exit,
    /// call `handle_fn` with the respective IoOperation to perform the mmio read or write,
    /// and set the return data in the vcpu so that the vcpu can resume running.
    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        let mut status: WHV_EMULATOR_STATUS = Default::default();
        let mut ctx = InstructionEmulatorContext {
            vm_partition: self.vm_partition.clone(),
            index: self.index,
            handle_mmio: Some(handle_fn),
            handle_io: None,
        };
        // safe as long as all callbacks occur before this fn returns.
        check_whpx!(unsafe {
            WHvEmulatorTryMmioEmulation(
                self.instruction_emulator.handle,
                &mut ctx as *mut _ as *mut c_void,
                &self.last_exit_context.VpContext,
                &self.last_exit_context.__bindgen_anon_1.MemoryAccess,
                &mut status,
            )
        })?;
        // safe because we trust the kernel to fill in the union field properly.
        let success = unsafe { status.__bindgen_anon_1.EmulationSuccessful() > 0 };
        if success {
            Ok(())
        } else {
            // safe because we trust the kernel to fill in the union field properly.
            Err(Error::new(unsafe { status.AsUINT32 }))
        }
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Io`.
    ///
    /// Once called, it will determine whether an io in or io out was the reason for the io exit,
    /// call `handle_fn` with the respective IoOperation to perform the io in or io out,
    /// and set the return data in the vcpu so that the vcpu can resume running.
    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        let mut status: WHV_EMULATOR_STATUS = Default::default();
        let mut ctx = InstructionEmulatorContext {
            vm_partition: self.vm_partition.clone(),
            index: self.index,
            handle_mmio: None,
            handle_io: Some(handle_fn),
        };
        // safe as long as all callbacks occur before this fn returns.
        check_whpx!(unsafe {
            WHvEmulatorTryIoEmulation(
                self.instruction_emulator.handle,
                &mut ctx as *mut _ as *mut c_void,
                &self.last_exit_context.VpContext,
                &self.last_exit_context.__bindgen_anon_1.IoPortAccess,
                &mut status,
            )
        })?; // safe because we trust the kernel to fill in the union field properly.
        let success = unsafe { status.__bindgen_anon_1.EmulationSuccessful() > 0 };
        if success {
            Ok(())
        } else {
            // safe because we trust the kernel to fill in the union field properly.
            Err(Error::new(unsafe { status.AsUINT32 }))
        }
    }

    /// this is unhandled currently since we don't emulate hypercall instructions for whpx.
    fn handle_hyperv_hypercall(&self, _func: &mut dyn FnMut(HypervHypercall) -> u64) -> Result<()> {
        Ok(())
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::RdMsr`,
    /// and in the same thread as run.
    ///
    /// It will put `data` into the user buffer and return.
    fn handle_rdmsr(&self, _data: u64) -> Result<()> {
        // TODO(b/235691411): Implement.
        Err(Error::new(libc::ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::WrMsr`,
    /// and in the same thread as run.
    fn handle_wrmsr(&self) {
        // TODO(b/235691411): Implement.
    }

    #[allow(non_upper_case_globals)]
    fn run(&mut self) -> Result<VcpuExit> {
        // safe because we own this whpx virtual processor index, and assume the vm partition is still valid
        let exit_context_ptr = Arc::as_ptr(&self.last_exit_context);
        check_whpx!(unsafe {
            WHvRunVirtualProcessor(
                self.vm_partition.partition,
                self.index,
                exit_context_ptr as *mut WHV_RUN_VP_EXIT_CONTEXT as *mut c_void,
                size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )
        })?;

        match self.last_exit_context.ExitReason {
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone => Ok(VcpuExit::Unknown),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess => Ok(VcpuExit::Mmio),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess => Ok(VcpuExit::Io),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException => {
                Ok(VcpuExit::UnrecoverableException)
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue => {
                Ok(VcpuExit::InvalidVpRegister)
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature => {
                Ok(VcpuExit::UnsupportedFeature)
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64InterruptWindow => {
                Ok(VcpuExit::IrqWindowOpen)
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Halt => Ok(VcpuExit::Hlt),
            // additional exits that are configurable
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64ApicEoi => {
                // safe because we trust the kernel to fill in the union field properly.
                let vector = unsafe {
                    self.last_exit_context
                        .__bindgen_anon_1
                        .ApicEoi
                        .InterruptVector as u8
                };
                Ok(VcpuExit::IoapicEoi { vector })
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess => {
                // Safe because we know this was an MSR access exit.
                let id = unsafe { self.last_exit_context.__bindgen_anon_1.MsrAccess.MsrNumber };

                // Safe because we know this was an MSR access exit
                let is_write = unsafe {
                    self.last_exit_context
                        .__bindgen_anon_1
                        .MsrAccess
                        .AccessInfo
                        .__bindgen_anon_1
                        .IsWrite()
                        == 1
                };
                if is_write {
                    // Safe because we know this was an MSR access exit
                    let value = unsafe {
                        // WRMSR writes the contents of registers EDX:EAX into the 64-bit model
                        // specific register
                        (self.last_exit_context.__bindgen_anon_1.MsrAccess.Rdx << 32)
                            | (self.last_exit_context.__bindgen_anon_1.MsrAccess.Rax & 0xffffffff)
                    };
                    self.handle_msr_write(id, value)?;
                } else {
                    self.handle_msr_read(id)?;
                }
                Ok(VcpuExit::MsrAccess)
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid => {
                // Safe because we know this was a CPUID exit.
                let entry = unsafe {
                    CpuIdEntry {
                        function: self.last_exit_context.__bindgen_anon_1.CpuidAccess.Rax as u32,
                        index: self.last_exit_context.__bindgen_anon_1.CpuidAccess.Rcx as u32,
                        flags: 0,
                        cpuid: CpuidResult {
                            eax: self
                                .last_exit_context
                                .__bindgen_anon_1
                                .CpuidAccess
                                .DefaultResultRax as u32,
                            ebx: self
                                .last_exit_context
                                .__bindgen_anon_1
                                .CpuidAccess
                                .DefaultResultRbx as u32,
                            ecx: self
                                .last_exit_context
                                .__bindgen_anon_1
                                .CpuidAccess
                                .DefaultResultRcx as u32,
                            edx: self
                                .last_exit_context
                                .__bindgen_anon_1
                                .CpuidAccess
                                .DefaultResultRdx as u32,
                        },
                    }
                };
                Ok(VcpuExit::Cpuid { entry })
            }
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException => Ok(VcpuExit::Exception),
            // undocumented exit calls from the header file, WinHvPlatformDefs.h.
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Rdtsc => Ok(VcpuExit::RdTsc),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64ApicSmiTrap => Ok(VcpuExit::ApicSmiTrap),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonHypercall => Ok(VcpuExit::Hypercall),
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64ApicInitSipiTrap => {
                Ok(VcpuExit::ApicInitSipiTrap)
            }
            // exit caused by host cancellation thorugh WHvCancelRunVirtualProcessor,
            WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled => Ok(VcpuExit::Canceled),
            r => panic!("unknown exit reason: {}", r),
        }
    }
}

impl VcpuX86_64 for WhpxVcpu {
    /// Sets or clears the flag that requests the VCPU to exit when it becomes possible to inject
    /// interrupts into the guest.
    fn set_interrupt_window_requested(&self, requested: bool) {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] =
            [WHV_REGISTER_NAME_WHvX64RegisterDeliverabilityNotifications];
        let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER__bindgen_ty_1 =
            Default::default();
        notifications.set_InterruptNotification(if requested { 1 } else { 0 });
        let notify_register = WHV_REGISTER_VALUE {
            DeliverabilityNotifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER {
                __bindgen_anon_1: notifications,
            },
        };
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                &notify_register as *const WHV_REGISTER_VALUE,
            )
        })
        .unwrap();
    }

    /// Checks if we can inject an interrupt into the VCPU.
    fn ready_for_interrupt(&self) -> bool {
        // safe because InterruptionPending bit is always valid in ExecutionState struct
        let pending = unsafe {
            self.last_exit_context
                .VpContext
                .ExecutionState
                .__bindgen_anon_1
                .InterruptionPending()
        };
        // safe because InterruptShadow bit is always valid in ExecutionState struct
        let shadow = unsafe {
            self.last_exit_context
                .VpContext
                .ExecutionState
                .__bindgen_anon_1
                .InterruptShadow()
        };

        let eflags = self.last_exit_context.VpContext.Rflags;
        const IF_MASK: u64 = 0x00000200;

        // can't inject an interrupt if InterruptShadow or InterruptPending bits are set, or if
        // the IF flag is clear
        shadow == 0 && pending == 0 && (eflags & IF_MASK) != 0
    }

    /// Injects interrupt vector `irq` into the VCPU.
    fn interrupt(&self, irq: u32) -> Result<()> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] =
            [WHV_REGISTER_NAME_WHvRegisterPendingInterruption];
        let mut pending_interrupt: WHV_X64_PENDING_INTERRUPTION_REGISTER__bindgen_ty_1 =
            Default::default();
        pending_interrupt.set_InterruptionPending(1);
        pending_interrupt
            .set_InterruptionType(WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingInterrupt as u32);
        pending_interrupt.set_InterruptionVector(irq);
        let interrupt = WHV_REGISTER_VALUE {
            PendingInterruption: WHV_X64_PENDING_INTERRUPTION_REGISTER {
                __bindgen_anon_1: pending_interrupt,
            },
        };
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                &interrupt as *const WHV_REGISTER_VALUE,
            )
        })
    }

    /// Injects a non-maskable interrupt into the VCPU.
    fn inject_nmi(&self) -> Result<()> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] =
            [WHV_REGISTER_NAME_WHvRegisterPendingInterruption];
        let mut pending_interrupt: WHV_X64_PENDING_INTERRUPTION_REGISTER__bindgen_ty_1 =
            Default::default();
        pending_interrupt.set_InterruptionPending(1);
        pending_interrupt
            .set_InterruptionType(WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingNmi as u32);
        const NMI_VECTOR: u32 = 2; // 2 is the NMI vector.
        pending_interrupt.set_InterruptionVector(NMI_VECTOR);
        let interrupt = WHV_REGISTER_VALUE {
            PendingInterruption: WHV_X64_PENDING_INTERRUPTION_REGISTER {
                __bindgen_anon_1: pending_interrupt,
            },
        };
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                &interrupt as *const WHV_REGISTER_VALUE,
            )
        })
    }

    /// Gets the VCPU general purpose registers.
    fn get_regs(&self) -> Result<Regs> {
        let mut whpx_regs: WhpxRegs = Default::default();
        let reg_names = WhpxRegs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_regs.as_mut_ptr(),
            )
        })?;
        Ok(Regs::from(&whpx_regs))
    }

    /// Sets the VCPU general purpose registers.
    fn set_regs(&self, regs: &Regs) -> Result<()> {
        let whpx_regs = WhpxRegs::from(regs);
        let reg_names = WhpxRegs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_regs.as_ptr(),
            )
        })
    }

    /// Gets the VCPU special registers.
    fn get_sregs(&self) -> Result<Sregs> {
        let mut whpx_sregs: WhpxSregs = Default::default();
        let reg_names = WhpxSregs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_sregs.as_mut_ptr(),
            )
        })?;
        Ok(Sregs::from(&whpx_sregs))
    }

    /// Sets the VCPU special registers.
    fn set_sregs(&self, sregs: &Sregs) -> Result<()> {
        let whpx_sregs = WhpxSregs::from(sregs);
        let reg_names = WhpxSregs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_sregs.as_ptr(),
            )
        })
    }

    /// Gets the VCPU FPU registers.
    fn get_fpu(&self) -> Result<Fpu> {
        let mut whpx_fpu: WhpxFpu = Default::default();
        let reg_names = WhpxFpu::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_fpu.as_mut_ptr(),
            )
        })?;
        Ok(Fpu::from(&whpx_fpu))
    }

    /// Sets the VCPU FPU registers.
    fn set_fpu(&self, fpu: &Fpu) -> Result<()> {
        let whpx_fpu = WhpxFpu::from(fpu);
        let reg_names = WhpxFpu::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_fpu.as_ptr(),
            )
        })
    }

    /// Gets the VCPU XSAVE.
    fn get_xsave(&self) -> Result<Xsave> {
        let mut empty_buffer = [0u8; 1];
        let mut needed_buf_size: u32 = 0;

        // Find out how much space is needed for XSAVEs.
        let res = unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.vm_partition.partition,
                self.index,
                empty_buffer.as_mut_ptr() as *mut _,
                0,
                &mut needed_buf_size,
            )
        };
        if res != WHV_E_INSUFFICIENT_BUFFER.0 {
            // This should always work, so if it doesn't, we'll return unsupported.
            error!("failed to get size of vcpu xsave");
            return Err(Error::new(EIO));
        }

        let mut xsave = Xsave::new(needed_buf_size as usize);
        // SAFETY: xsave_data is valid for the duration of the FFI call, and we pass its length in
        // bytes so writes are bounded within the buffer.
        check_whpx!(unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.vm_partition.partition,
                self.index,
                xsave.as_mut_ptr(),
                xsave.len() as u32,
                &mut needed_buf_size,
            )
        })?;
        Ok(xsave)
    }

    /// Sets the VCPU XSAVE.
    fn set_xsave(&self, xsave: &Xsave) -> Result<()> {
        // SAFETY: the xsave buffer is valid for the duration of the FFI call, and we pass its
        // length in bytes so reads are bounded within the buffer.
        check_whpx!(unsafe {
            WHvSetVirtualProcessorXsaveState(
                self.vm_partition.partition,
                self.index,
                xsave.as_ptr(),
                xsave.len() as u32,
            )
        })
    }

    fn get_interrupt_state(&self) -> Result<serde_json::Value> {
        let mut whpx_interrupt_regs: WhpxInterruptRegs = Default::default();
        let reg_names = WhpxInterruptRegs::get_register_names();
        // SAFETY: we have enough space for all the registers & the memory lives for the duration
        // of the FFI call.
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_interrupt_regs.as_mut_ptr(),
            )
        })?;

        serde_json::to_value(whpx_interrupt_regs.into_serializable()).map_err(|e| {
            error!("failed to serialize interrupt state: {:?}", e);
            Error::new(EIO)
        })
    }

    fn set_interrupt_state(&self, data: serde_json::Value) -> Result<()> {
        let whpx_interrupt_regs =
            WhpxInterruptRegs::from_serializable(serde_json::from_value(data).map_err(|e| {
                error!("failed to serialize interrupt state: {:?}", e);
                Error::new(EIO)
            })?);
        let reg_names = WhpxInterruptRegs::get_register_names();
        // SAFETY: we have enough space for all the registers & the memory lives for the duration
        // of the FFI call.
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_interrupt_regs.as_ptr(),
            )
        })
    }

    /// Gets the VCPU debug registers.
    fn get_debugregs(&self) -> Result<DebugRegs> {
        let mut whpx_debugregs: WhpxDebugRegs = Default::default();
        let reg_names = WhpxDebugRegs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_debugregs.as_mut_ptr(),
            )
        })?;
        Ok(DebugRegs::from(&whpx_debugregs))
    }

    /// Sets the VCPU debug registers.
    fn set_debugregs(&self, debugregs: &DebugRegs) -> Result<()> {
        let whpx_debugregs = WhpxDebugRegs::from(debugregs);
        let reg_names = WhpxDebugRegs::get_register_names();
        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                reg_names as *const WHV_REGISTER_NAME,
                reg_names.len() as u32,
                whpx_debugregs.as_ptr(),
            )
        })
    }

    /// Gets the VCPU extended control registers.
    fn get_xcrs(&self) -> Result<Vec<Register>> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] = [WHV_REGISTER_NAME_WHvX64RegisterXCr0];
        let mut xcrs: [WHV_REGISTER_VALUE; 1] = Default::default();
        // safe because we have enough space for all the registers in whpx_regs
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                xcrs.as_mut_ptr(),
            )
        })?;
        let reg = Register {
            id: 0, // whpx only supports xcr0
            // safe because the union value, reg64, is safe to pull out assuming
            // kernel filled in the xcrs properly.
            value: unsafe { xcrs[0].Reg64 },
        };
        Ok(vec![reg])
    }

    /// Sets the VCPU extended control registers.
    fn set_xcrs(&self, xcrs: &[Register]) -> Result<()> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] = [WHV_REGISTER_NAME_WHvX64RegisterXCr0];
        let whpx_xcrs = xcrs
            .iter()
            .filter_map(|reg| match reg.id {
                0 => Some(WHV_REGISTER_VALUE { Reg64: reg.value }),
                _ => None,
            })
            .collect::<Vec<WHV_REGISTER_VALUE>>();
        if !whpx_xcrs.is_empty() {
            // safe because we have enough space for all the registers in whpx_xcrs
            check_whpx!(unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.vm_partition.partition,
                    self.index,
                    &REG_NAMES as *const WHV_REGISTER_NAME,
                    REG_NAMES.len() as u32,
                    whpx_xcrs.as_ptr(),
                )
            })
        } else {
            // invalid xcr register provided
            Err(Error::new(ENXIO))
        }
    }

    /// Gets the model-specific registers.  `msrs` specifies the MSR indexes to be queried, and
    /// on success contains their indexes and values.
    fn get_msrs(&self, msrs: &mut Vec<Register>) -> Result<()> {
        let msr_names = get_msr_names(msrs);
        let mut buffer: Vec<WHV_REGISTER_VALUE> = vec![Default::default(); msr_names.len()];
        // safe because we have enough space for all the registers in whpx_regs
        check_whpx!(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                msr_names.as_ptr(),
                msr_names.len() as u32,
                buffer.as_mut_ptr(),
            )
        })?;

        msrs.retain(|&msr| VALID_MSRS.contains_key(&msr.id));
        if buffer.len() != msrs.len() {
            panic!("mismatch of valid whpx msr registers and returned registers");
        }
        for (i, msr) in msrs.iter_mut().enumerate() {
            // safe because Reg64 will be a valid union value for all msrs
            msr.value = unsafe { buffer[i].Reg64 };
        }
        Ok(())
    }

    fn get_all_msrs(&self) -> Result<Vec<Register>> {
        // Note that some members of VALID_MSRS cannot be fetched from WHPX with
        // WHvGetVirtualProcessorRegisters per the HTLFS, so we enumerate all of
        // permitted MSRs here.
        //
        // We intentionally exclude WHvRegisterPendingInterruption and
        // WHvRegisterInterruptState because they are included in
        // get_interrupt_state.
        //
        // We also exclude MSR_TSC, because on WHPX, we will use virtio-pvclock
        // to restore the guest clocks. Note that this will be *guest aware*
        // snapshotting. We may in the future add guest unaware snapshotting
        // for Windows, in which case we will want to save/restore TSC such that
        // the guest does not observe any change.
        let mut registers = vec![
            Register {
                id: MSR_EFER,
                ..Default::default()
            },
            Register {
                id: MSR_KERNEL_GS_BASE,
                ..Default::default()
            },
            Register {
                id: MSR_APIC_BASE,
                ..Default::default()
            },
            Register {
                id: MSR_SYSENTER_CS,
                ..Default::default()
            },
            Register {
                id: MSR_SYSENTER_EIP,
                ..Default::default()
            },
            Register {
                id: MSR_SYSENTER_ESP,
                ..Default::default()
            },
            Register {
                id: MSR_STAR,
                ..Default::default()
            },
            Register {
                id: MSR_LSTAR,
                ..Default::default()
            },
            Register {
                id: MSR_CSTAR,
                ..Default::default()
            },
            Register {
                id: MSR_SFMASK,
                ..Default::default()
            },
        ];
        self.get_msrs(&mut registers)?;
        Ok(registers)
    }

    /// Sets the model-specific registers.
    fn set_msrs(&self, msrs: &[Register]) -> Result<()> {
        let msr_names = get_msr_names(msrs);
        let whpx_msrs = msrs
            .iter()
            .filter_map(|msr| {
                if VALID_MSRS.contains_key(&msr.id) {
                    Some(WHV_REGISTER_VALUE { Reg64: msr.value })
                } else {
                    None
                }
            })
            .collect::<Vec<WHV_REGISTER_VALUE>>();

        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                msr_names.as_ptr(),
                msr_names.len() as u32,
                whpx_msrs.as_ptr(),
            )
        })
    }

    /// Sets up the data returned by the CPUID instruction.
    /// For WHPX, this is not valid on the vcpu, and needs to be setup on the vm.
    fn set_cpuid(&self, _cpuid: &CpuId) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    /// This function should be called after `Vcpu::run` returns `VcpuExit::Cpuid`, and `entry`
    /// should represent the result of emulating the CPUID instruction. The `handle_cpuid` function
    /// will then set the appropriate registers on the vcpu.
    fn handle_cpuid(&mut self, entry: &CpuIdEntry) -> Result<()> {
        // Verify that we're only being called in a situation where the last exit reason was
        // ExitReasonX64Cpuid
        if self.last_exit_context.ExitReason != WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid {
            return Err(Error::new(EINVAL));
        }

        // Get the next rip from the exit context
        let rip = self.last_exit_context.VpContext.Rip
            + self.last_exit_context.VpContext.InstructionLength() as u64;

        const REG_NAMES: [WHV_REGISTER_NAME; 5] = [
            WHV_REGISTER_NAME_WHvX64RegisterRip,
            WHV_REGISTER_NAME_WHvX64RegisterRax,
            WHV_REGISTER_NAME_WHvX64RegisterRbx,
            WHV_REGISTER_NAME_WHvX64RegisterRcx,
            WHV_REGISTER_NAME_WHvX64RegisterRdx,
        ];

        let values = vec![
            WHV_REGISTER_VALUE { Reg64: rip },
            WHV_REGISTER_VALUE {
                Reg64: entry.cpuid.eax as u64,
            },
            WHV_REGISTER_VALUE {
                Reg64: entry.cpuid.ebx as u64,
            },
            WHV_REGISTER_VALUE {
                Reg64: entry.cpuid.ecx as u64,
            },
            WHV_REGISTER_VALUE {
                Reg64: entry.cpuid.edx as u64,
            },
        ];

        // safe because we have enough space for all the registers
        check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE,
            )
        })
    }

    /// Gets the system emulated hyper-v CPUID values.
    /// For WHPX, this is not valid on the vcpu, and needs to be setup on the vm.
    fn get_hyperv_cpuid(&self) -> Result<CpuId> {
        Err(Error::new(ENXIO))
    }

    /// Sets up debug registers and configure vcpu for handling guest debug events.
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        // TODO(b/173807302): Implement this
        Err(Error::new(ENOENT))
    }

    fn get_tsc_offset(&self) -> Result<u64> {
        // Although WHPX has the WHV_REGISTER_NAME_WHvX64RegisterTscVirtualOffset register, calling
        // WHvGetVirtualProcessorRegisters always returns 0 for it.
        get_tsc_offset_from_msr(self)
    }

    fn set_tsc_offset(&self, offset: u64) -> Result<()> {
        const REG_NAMES: [WHV_REGISTER_NAME; 1] =
            [WHV_REGISTER_NAME_WHvX64RegisterTscVirtualOffset];

        let values = vec![WHV_REGISTER_VALUE { Reg64: offset }];

        // Try to use the built-in API for setting the TSC offset
        if check_whpx!(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm_partition.partition,
                self.index,
                &REG_NAMES as *const WHV_REGISTER_NAME,
                REG_NAMES.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE,
            )
        })
        .is_ok()
        {
            return Ok(());
        }

        // Use the default MSR-based implementation
        set_tsc_offset_via_msr(self, offset)
    }
}

fn get_msr_names(msrs: &[Register]) -> Vec<WHV_REGISTER_NAME> {
    msrs.iter()
        .filter_map(|reg| VALID_MSRS.get(&reg.id).copied())
        .collect::<Vec<WHV_REGISTER_NAME>>()
}

// run calls are tested with the integration tests since the full vcpu needs to be setup for it.
#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use super::*;
    use crate::VmX86_64;

    fn new_vm(cpu_count: usize, mem: GuestMemory) -> WhpxVm {
        let whpx = Whpx::new().expect("failed to instantiate whpx");
        let local_apic_supported = Whpx::check_whpx_feature(WhpxFeature::LocalApicEmulation)
            .expect("failed to get whpx features");
        WhpxVm::new(
            &whpx,
            cpu_count,
            mem,
            CpuId::new(0),
            local_apic_supported,
            None,
        )
        .expect("failed to create whpx vm")
    }

    #[test]
    fn try_clone() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");
        let vcpu: &WhpxVcpu = vcpu.downcast_ref().expect("Expected a WhpxVcpu");
        let _vcpu_clone = vcpu.try_clone().expect("failed to clone whpx vcpu");
    }

    #[test]
    fn index() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 2;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let mut vcpu = vm.create_vcpu(0).expect("failed to create vcpu");
        let vcpu0: &WhpxVcpu = vcpu.downcast_ref().expect("Expected a WhpxVcpu");
        assert_eq!(vcpu0.index, 0);
        vcpu = vm.create_vcpu(1).expect("failed to create vcpu");
        let vcpu1: &WhpxVcpu = vcpu.downcast_ref().expect("Expected a WhpxVcpu");
        assert_eq!(vcpu1.index, 1);
    }

    #[test]
    fn get_regs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        vcpu.get_regs().expect("failed to get regs");
    }

    #[test]
    fn set_regs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut regs = vcpu.get_regs().expect("failed to get regs");
        let new_val = regs.rax + 2;
        regs.rax = new_val;

        vcpu.set_regs(&regs).expect("failed to set regs");
        let new_regs = vcpu.get_regs().expect("failed to get regs");
        assert_eq!(new_regs.rax, new_val);
    }

    #[test]
    fn debugregs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut dregs = vcpu.get_debugregs().unwrap();
        dregs.dr7 += 13;
        vcpu.set_debugregs(&dregs).unwrap();
        let dregs2 = vcpu.get_debugregs().unwrap();
        assert_eq!(dregs.dr7, dregs2.dr7);
    }

    #[test]
    fn sregs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cs.base += 7;
        vcpu.set_sregs(&sregs).unwrap();
        let sregs2 = vcpu.get_sregs().unwrap();
        assert_eq!(sregs.cs.base, sregs2.cs.base);
    }

    #[test]
    fn fpu() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut fpu = vcpu.get_fpu().unwrap();
        fpu.fpr[0][0] += 3;
        vcpu.set_fpu(&fpu).unwrap();
        let fpu2 = vcpu.get_fpu().unwrap();
        assert_eq!(fpu.fpr[0][0], fpu2.fpr[0][0]);
    }

    #[test]
    fn xcrs() {
        if !Whpx::is_enabled() {
            return;
        }
        let whpx = Whpx::new().expect("failed to instantiate whpx");
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");
        // check xsave support
        if !whpx.check_capability(HypervisorCap::Xcrs) {
            return;
        }

        let mut xcrs = vcpu.get_xcrs().unwrap();
        xcrs[0].value = 1;
        vcpu.set_xcrs(&xcrs).unwrap();
        let xcrs2 = vcpu.get_xcrs().unwrap();
        assert_eq!(xcrs[0].value, xcrs2[0].value);
    }

    #[test]
    fn set_msrs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut msrs = vec![Register {
            id: MSR_KERNEL_GS_BASE,
            value: 42,
        }];
        vcpu.set_msrs(&msrs).unwrap();

        msrs[0].value = 0;
        vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(msrs.len(), 1);
        assert_eq!(msrs[0].id, MSR_KERNEL_GS_BASE);
        assert_eq!(msrs[0].value, 42);
    }

    #[test]
    fn get_msrs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut msrs = vec![
            // This one should succeed
            Register {
                id: MSR_TSC,
                ..Default::default()
            },
            // This one will fail to fetch
            Register {
                id: MSR_TSC + 1,
                ..Default::default()
            },
        ];
        vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(msrs.len(), 1);
    }

    #[test]
    fn set_efer() {
        if !Whpx::is_enabled() {
            return;
        }
        // EFER Bits
        const EFER_SCE: u64 = 0x00000001;
        const EFER_LME: u64 = 0x00000100;
        const EFER_LMA: u64 = 0x00000400;
        const X86_CR0_PE: u64 = 0x1;
        const X86_CR0_PG: u64 = 0x80000000;
        const X86_CR4_PAE: u64 = 0x20;

        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let mut sregs = vcpu.get_sregs().expect("failed to get sregs");
        // Initial value should be 0
        assert_eq!(sregs.efer, 0);

        // Enable and activate long mode
        sregs.cr0 |= X86_CR0_PE; // enable protected mode
        sregs.cr0 |= X86_CR0_PG; // enable paging
        sregs.cr4 |= X86_CR4_PAE; // enable physical address extension
        sregs.efer = EFER_LMA | EFER_LME;
        vcpu.set_sregs(&sregs).expect("failed to set sregs");

        // Verify that setting stuck
        let sregs = vcpu.get_sregs().expect("failed to get sregs");
        assert_eq!(sregs.efer, EFER_LMA | EFER_LME);
        assert_eq!(sregs.cr0 & X86_CR0_PE, X86_CR0_PE);
        assert_eq!(sregs.cr0 & X86_CR0_PG, X86_CR0_PG);
        assert_eq!(sregs.cr4 & X86_CR4_PAE, X86_CR4_PAE);

        let mut efer_reg = vec![Register {
            id: MSR_EFER,
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

    #[test]
    fn get_and_set_xsave_smoke() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        // XSAVE is essentially opaque for our purposes. We just want to make sure our syscalls
        // succeed.
        let xsave = vcpu.get_xsave().unwrap();
        vcpu.set_xsave(&xsave).unwrap();
    }

    #[test]
    fn get_and_set_interrupt_state_smoke() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        // For the sake of snapshotting, interrupt state is essentially opaque. We just want to make
        // sure our syscalls succeed.
        let interrupt_state = vcpu.get_interrupt_state().unwrap();
        vcpu.set_interrupt_state(interrupt_state).unwrap();
    }

    #[test]
    fn get_all_msrs() {
        if !Whpx::is_enabled() {
            return;
        }
        let cpu_count = 1;
        let mem =
            GuestMemory::new(&[(GuestAddress(0), 0x1000)]).expect("failed to create guest memory");
        let vm = new_vm(cpu_count, mem);
        let vcpu = vm.create_vcpu(0).expect("failed to create vcpu");

        let all_msrs = vcpu.get_all_msrs().unwrap();

        // Our MSR buffer is init'ed to zeros in the registers. The APIC base will be non-zero, so
        // by asserting that we know the MSR fetch actually did get us data.
        let apic_base = all_msrs.iter().find(|reg| reg.id == MSR_APIC_BASE).unwrap();
        assert_ne!(apic_base.value, 0);
    }
}
