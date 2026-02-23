// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! HVF VCPU implementation for aarch64.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use aarch64_sys_reg::AArch64SysRegId;
use base::Error;
use base::Result;
use snapshot::AnySnapshot;
use sync::Mutex;
use vm_memory::GuestAddress;

use super::bindings;
use super::vm::IoEventEntry;
use crate::IoOperation;
use crate::IoParams;
use crate::PsciVersion;
use crate::Vcpu;
use crate::VcpuAArch64;
use crate::VcpuExit;
use crate::VcpuFeature;
use crate::VcpuRegAArch64;

/// State captured from the last VCPU exit for MMIO handling.
struct MmioState {
    address: u64,
    size: usize,
    is_write: bool,
    data: u64,
    reg_num: u32,
}

/// Cached register value for deferred application.
enum CachedReg {
    Gpr(bindings::hv_reg_t, u64),
    SysReg(bindings::hv_sys_reg_t, u64),
}

/// HVF VCPU implementation.
///
/// Apple's HVF requires `hv_vcpu_run` to be called on the same thread that
/// called `hv_vcpu_create`. Since crosvm creates VCPUs in the main thread
/// but runs them in per-VCPU threads, we defer the actual `hv_vcpu_create`
/// call to the first `run()` invocation. Register writes before that point
/// are cached and applied at creation time.
pub struct HvfVcpu {
    /// VCPU handle from HVF (0 until created on the running thread)
    vcpu: bindings::hv_vcpu_t,
    /// Pointer to the VCPU exit information structure (null until created)
    exit: *mut bindings::hv_vcpu_exit_t,
    /// VCPU identifier
    id: usize,
    /// Flag for requesting an immediate exit
    immediate_exit: Arc<AtomicBool>,
    /// Shared IO events for userspace dispatch (reserved for future ioeventfd support)
    _io_events: Arc<Mutex<Vec<IoEventEntry>>>,
    /// Last MMIO state for handle_mmio
    last_mmio: Mutex<Option<MmioState>>,
    /// Whether the HVF vcpu has been created on the running thread
    created: std::sync::atomic::AtomicBool,
    /// Cached register writes to apply when the VCPU is created on the running thread
    cached_regs: Mutex<Vec<CachedReg>>,
    /// Guest memory reference for re-mapping in ensure_created
    guest_mem: vm_memory::GuestMemory,
    /// Whether the vtimer is currently masked (awaiting guest handling)
    vtimer_masked: bool,
}

// SAFETY: HvfVcpu is bound to a thread but the struct can be sent
unsafe impl Send for HvfVcpu {}
// SAFETY: The mutable state is protected by Mutex
unsafe impl Sync for HvfVcpu {}

impl HvfVcpu {
    /// Creates a new HVF VCPU placeholder.
    ///
    /// The actual `hv_vcpu_create` is deferred to `ensure_created()` which
    /// runs on the VCPU thread.
    pub(super) fn new(id: usize, io_events: Arc<Mutex<Vec<IoEventEntry>>>, guest_mem: vm_memory::GuestMemory) -> Result<Self> {
        Ok(HvfVcpu {
            vcpu: 0,
            exit: std::ptr::null_mut(),
            id,
            immediate_exit: Arc::new(AtomicBool::new(false)),
            _io_events: io_events,
            last_mmio: Mutex::new(None),
            created: std::sync::atomic::AtomicBool::new(false),
            cached_regs: Mutex::new(Vec::new()),
            guest_mem,
            vtimer_masked: false,
        })
    }

    /// Actually create the HVF VCPU on the current thread and apply cached registers.
    ///
    /// This must be called from the thread that will subsequently call `hv_vcpu_run`.
    fn ensure_created(&mut self) -> Result<()> {
        if self.created.load(Ordering::SeqCst) {
            return Ok(());
        }

        let mut vcpu: bindings::hv_vcpu_t = 0;
        let mut exit: *mut bindings::hv_vcpu_exit_t = std::ptr::null_mut();

        // SAFETY: We pass valid pointers to receive the vcpu handle and exit struct
        let ret = unsafe {
            bindings::hv_vcpu_create(
                &mut vcpu,
                &mut exit as *mut *mut bindings::hv_vcpu_exit_t,
                std::ptr::null_mut(),
            )
        };
        if ret != bindings::HV_SUCCESS {
            base::error!("hv_vcpu_create failed for vcpu {}: 0x{:08x}", self.id, ret as u32);
            return Err(Error::new(libc::EIO));
        }

        self.vcpu = vcpu;
        self.exit = exit;
        self.created.store(true, Ordering::SeqCst);

        // Re-map guest memory from this VCPU's thread.
        // On some macOS versions, hv_vm_map done on the main thread may not
        // be fully visible to VCPUs created on other threads. We unmap and
        // re-map to ensure the Stage 2 page tables are properly set up.
        for region in self.guest_mem.regions() {
            let flags: u64 = (bindings::HV_MEMORY_READ | bindings::HV_MEMORY_WRITE | bindings::HV_MEMORY_EXEC).into();
            // Unmap first (ignore errors - might not have been mapped yet from this thread's perspective)
            unsafe { bindings::hv_vm_unmap(region.guest_addr.offset(), region.size) };
            let ret = unsafe {
                bindings::hv_vm_map(
                    region.host_addr as *mut std::ffi::c_void,
                    region.guest_addr.offset(),
                    region.size,
                    flags,
                )
            };
            if ret != bindings::HV_SUCCESS {
                base::error!("vcpu {}: re-map guest memory failed: 0x{:08x}", self.id, ret as u32);
            }
        }

        let num_cached = self.cached_regs.lock().len();
        base::info!("vcpu {}: created on thread, applying {} cached registers", self.id, num_cached);

        // Apply all cached register writes
        for cached in self.cached_regs.lock().drain(..) {
            match cached {
                CachedReg::Gpr(reg, value) => {
                    let ret = unsafe { bindings::hv_vcpu_set_reg(self.vcpu, reg, value) };
                    if ret != bindings::HV_SUCCESS {
                        base::error!("hv_vcpu_set_reg({}) failed: 0x{:08x}", reg, ret as u32);
                        return Err(Error::new(libc::EIO));
                    }
                }
                CachedReg::SysReg(reg, value) => {
                    let ret = unsafe { bindings::hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
                    if ret != bindings::HV_SUCCESS {
                        base::error!("hv_vcpu_set_sys_reg({}) failed: 0x{:08x}", reg, ret as u32);
                        return Err(Error::new(libc::EIO));
                    }
                }
            }
        }

        Ok(())
    }

    /// Gets a general-purpose register value.
    fn get_reg(&self, reg: bindings::hv_reg_t) -> Result<u64> {
        if !self.created.load(Ordering::SeqCst) {
            // Check cache for the value
            for cached in self.cached_regs.lock().iter() {
                if let CachedReg::Gpr(r, v) = cached {
                    if *r == reg { return Ok(*v); }
                }
            }
            return Ok(0); // Default
        }
        let mut value: u64 = 0;
        // SAFETY: vcpu is valid and value pointer is valid
        let ret = unsafe { bindings::hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(value)
    }

    /// Sets a general-purpose register value.
    fn set_reg(&self, reg: bindings::hv_reg_t, value: u64) -> Result<()> {
        if !self.created.load(Ordering::SeqCst) {
            self.cached_regs.lock().push(CachedReg::Gpr(reg, value));
            return Ok(());
        }
        // SAFETY: vcpu is valid
        let ret = unsafe { bindings::hv_vcpu_set_reg(self.vcpu, reg, value) };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(())
    }

    /// Gets a system register value.
    fn get_sys_reg(&self, reg: bindings::hv_sys_reg_t) -> Result<u64> {
        if !self.created.load(Ordering::SeqCst) {
            // Check cache for the value
            for cached in self.cached_regs.lock().iter() {
                if let CachedReg::SysReg(r, v) = cached {
                    if *r == reg { return Ok(*v); }
                }
            }
            return Ok(0); // Default
        }
        let mut value: u64 = 0;
        // SAFETY: vcpu is valid and value pointer is valid
        let ret = unsafe { bindings::hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value) };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(value)
    }

    /// Sets a system register value.
    fn set_sys_reg(&self, reg: bindings::hv_sys_reg_t, value: u64) -> Result<()> {
        if !self.created.load(Ordering::SeqCst) {
            self.cached_regs.lock().push(CachedReg::SysReg(reg, value));
            return Ok(());
        }
        // SAFETY: vcpu is valid
        let ret = unsafe { bindings::hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(())
    }

    /// Advances the PC past the current instruction.
    fn advance_pc(&self) -> Result<()> {
        let pc = self.get_reg(bindings::HV_REG_PC)?;
        // AArch64 instructions are 4 bytes
        self.set_reg(bindings::HV_REG_PC, pc + 4)
    }

    /// Handles a PSCI call from the guest.
    ///
    /// Note: HVC/SMC are trapped instructions, so HVF already sets PC to the
    /// next instruction (preferred return address). We must NOT call advance_pc().
    fn handle_psci(&self, func_id: u32) -> Result<VcpuExit> {
        match func_id {
            // PSCI_VERSION
            0x84000000 => {
                // Return PSCI v1.0
                self.set_reg(bindings::HV_REG_X0, 0x00010000)?;
                Ok(VcpuExit::Intr)
            }
            // PSCI_CPU_ON (32-bit)
            0x84000003 => {
                Ok(VcpuExit::SystemEventReset)
            }
            // PSCI_CPU_ON (64-bit)
            0xC4000003 => {
                Ok(VcpuExit::SystemEventReset)
            }
            // PSCI_CPU_OFF
            0x84000002 => {
                Ok(VcpuExit::Shutdown(Ok(())))
            }
            // PSCI_SYSTEM_OFF
            0x84000008 => {
                Ok(VcpuExit::Shutdown(Ok(())))
            }
            // PSCI_SYSTEM_RESET
            0x84000009 => {
                Ok(VcpuExit::SystemEventReset)
            }
            // PSCI_FEATURES
            0x8400000A => {
                // Return success (features supported)
                self.set_reg(bindings::HV_REG_X0, 0)?;
                Ok(VcpuExit::Intr)
            }
            _ => {
                // Unknown PSCI call - return NOT_SUPPORTED (-1 sign-extended)
                self.set_reg(bindings::HV_REG_X0, 0xFFFF_FFFF)?;
                Ok(VcpuExit::Intr)
            }
        }
    }

    /// Maps a VcpuRegAArch64 to the HVF register constants.
    fn reg_to_hvf(&self, reg: VcpuRegAArch64) -> Option<HvfRegType> {
        match reg {
            VcpuRegAArch64::X(n) if n <= 30 => Some(HvfRegType::Gpr(n as u32)),
            VcpuRegAArch64::Sp => Some(HvfRegType::SysReg(bindings::HV_SYS_REG_SP_EL0)),
            VcpuRegAArch64::Pc => Some(HvfRegType::Gpr(bindings::HV_REG_PC)),
            VcpuRegAArch64::Pstate => Some(HvfRegType::Gpr(bindings::HV_REG_CPSR)),
            VcpuRegAArch64::System(sys_id) => {
                aarch64_sysreg_to_hvf(sys_id).map(HvfRegType::SysReg)
            }
            _ => None,
        }
    }
}

/// Type of HVF register (general-purpose or system).
enum HvfRegType {
    Gpr(bindings::hv_reg_t),
    SysReg(bindings::hv_sys_reg_t),
}

/// Converts an AArch64SysRegId to the HVF system register encoding.
fn aarch64_sysreg_to_hvf(id: AArch64SysRegId) -> Option<bindings::hv_sys_reg_t> {
    // HVF uses the same encoding as the ARM spec for system registers
    Some(id.encoded())
}

impl Vcpu for HvfVcpu {
    fn try_clone(&self) -> Result<Self> {
        // HVF VCPUs cannot be cloned - they are per-thread
        Err(Error::new(libc::ENOTSUP))
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    fn id(&self) -> usize {
        self.id
    }

    fn set_immediate_exit(&self, exit: bool) {
        self.immediate_exit.store(exit, Ordering::SeqCst);
        if exit {
            let mut vcpu = self.vcpu;
            // SAFETY: We pass a valid vcpu handle
            unsafe {
                bindings::hv_vcpus_exit(&mut vcpu, 1);
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn signal_handle(&self) -> crate::VcpuSignalHandle {
        unimplemented!("signal_handle is not used on macOS")
    }

    fn run(&mut self) -> Result<VcpuExit> {
        // Lazily create the VCPU on the running thread (HVF requirement)
        self.ensure_created()?;

        // Check for immediate exit request
        if self.immediate_exit.load(Ordering::SeqCst) {
            return Ok(VcpuExit::Canceled);
        }

        // Sync vtimer state before running: if the vtimer was masked (from a
        // previous HV_EXIT_REASON_VTIMER_ACTIVATED), check whether the guest
        // has handled the timer interrupt. If the timer condition is no longer
        // active, unmask the vtimer so it can fire again.
        if self.vtimer_masked {
            let ctl = self.get_sys_reg(bindings::HV_SYS_REG_CNTV_CTL_EL0)?;
            const TMR_CTL_ENABLE: u64 = 1 << 0;
            const TMR_CTL_IMASK: u64 = 1 << 1;
            const TMR_CTL_ISTATUS: u64 = 1 << 2;
            let irq_active = (ctl & (TMR_CTL_ENABLE | TMR_CTL_IMASK | TMR_CTL_ISTATUS))
                == (TMR_CTL_ENABLE | TMR_CTL_ISTATUS);
            if !irq_active {
                // SAFETY: vcpu is valid
                unsafe { bindings::hv_vcpu_set_vtimer_mask(self.vcpu, false); }
                self.vtimer_masked = false;
            }
        }

        // SAFETY: vcpu is valid (created on this thread)
        let ret = unsafe { bindings::hv_vcpu_run(self.vcpu) };
        if ret != bindings::HV_SUCCESS {
            base::error!("hv_vcpu_run failed: 0x{:08x}", ret as u32);
            return Err(Error::new(libc::EIO));
        }

        // SAFETY: exit pointer was set by hv_vcpu_create and remains valid
        let exit_info = unsafe { &*self.exit };

        match exit_info.reason {
            bindings::HV_EXIT_REASON_CANCELED => Ok(VcpuExit::Canceled),

            bindings::HV_EXIT_REASON_VTIMER_ACTIVATED => {
                // The vtimer fired. HVF automatically masks the vtimer when
                // it exits with VTIMER_ACTIVATED (preventing re-entry). We
                // track this locally and unmask in the vtimer sync logic
                // before hv_vcpu_run() once the guest has handled the timer
                // interrupt. Do NOT call hv_vcpu_set_vtimer_mask(true) here -
                // the explicit call can deassert the PPI from the in-kernel
                // GIC, preventing the guest from ever seeing the interrupt.
                self.vtimer_masked = true;
                Ok(VcpuExit::Intr)
            }

            bindings::HV_EXIT_REASON_EXCEPTION => {
                let syndrome = exit_info.exception.syndrome;
                let ec = bindings::syndrome_ec(syndrome);
                let iss = bindings::syndrome_iss(syndrome);

                match ec {
                    bindings::EC_DATAABORT_LOWER_EL => {
                        // MMIO access
                        let is_write = bindings::data_abort_is_write(iss);
                        let access_size = bindings::data_abort_access_size(iss);
                        let srt = bindings::data_abort_srt(iss);
                        let address = exit_info.exception.physical_address;

                        let data = if is_write {
                            self.get_reg(srt)?
                        } else {
                            0
                        };

                        *self.last_mmio.lock() = Some(MmioState {
                            address,
                            size: access_size,
                            is_write,
                            data,
                            reg_num: srt,
                        });

                        Ok(VcpuExit::Mmio)
                    }

                    bindings::EC_AA64_HVC => {
                        let func_id = self.get_reg(bindings::HV_REG_X0)? as u32;
                        self.handle_psci(func_id)
                    }

                    bindings::EC_AA64_SMC => {
                        let func_id = self.get_reg(bindings::HV_REG_X0)? as u32;
                        self.handle_psci(func_id)
                    }

                    bindings::EC_WFX_TRAP => {
                        // WFI/WFE - HVF already advances PC past the trapped instruction
                        Ok(VcpuExit::Hlt)
                    }

                    bindings::EC_INSTR_ABORT_LOWER_EL => {
                        // Instruction abort from guest.
                        let pa = exit_info.exception.physical_address;
                        let va = exit_info.exception.virtual_address;
                        let pc = self.get_reg(bindings::HV_REG_PC).unwrap_or(0);
                        let ifsc = iss & 0x3f;
                        base::error!(
                            "vcpu {}: IABT from guest: PC=0x{:x} VA=0x{:x} PA=0x{:x} IFSC=0x{:x}",
                            self.id, pc, va, pa, ifsc
                        );
                        Ok(VcpuExit::Exception)
                    }

                    bindings::EC_SYSTEMREGISTERTRAP => {
                        // System register access trap (MSR/MRS)
                        // Decode the ISS to identify the register and direction
                        let is_read = (iss & 1) != 0;
                        let rt = ((iss >> 5) & 0x1f) as u32;
                        let op0 = ((iss >> 20) & 0x3) as u32;
                        let op2 = ((iss >> 17) & 0x7) as u32;
                        let op1 = ((iss >> 14) & 0x7) as u32;
                        let crn = ((iss >> 10) & 0xf) as u32;
                        let crm = ((iss >> 1) & 0xf) as u32;

                        // Build system register encoding: op0:op1:crn:crm:op2
                        let sysreg_desc = format!(
                            "S{}_{}_C{}_C{}_{}",
                            op0, op1, crn, crm, op2
                        );

                        if is_read {
                            // For reads, write 0 to the destination register
                            // to avoid leaving stale/undefined values
                            if rt < 31 {
                                let _ = self.set_reg(rt, 0);
                            }
                            // Use debug! instead of warn! to avoid spam
                            base::debug!(
                                "vcpu {}: sysreg READ trap {} (rt=x{}) - returning 0",
                                self.id, sysreg_desc, rt
                            );
                        } else {
                            let val = if rt < 31 {
                                self.get_reg(rt).unwrap_or(0)
                            } else {
                                0 // XZR
                            };
                            // Use debug! instead of warn! to avoid spam
                            base::debug!(
                                "vcpu {}: sysreg WRITE trap {} (rt=x{}, val={:#x}) - dropped",
                                self.id, sysreg_desc, rt, val
                            );
                        }

                        // CRITICAL FIX: HVF does NOT automatically advance PC for sysreg traps
                        // (unlike HVC/SMC). We must manually advance it.
                        self.advance_pc()?;
                        Ok(VcpuExit::Intr)
                    }

                    _ => {
                        let pc = self.get_reg(bindings::HV_REG_PC).unwrap_or(0);
                        let far = exit_info.exception.virtual_address;
                        base::error!(
                            "vcpu {}: unhandled exception EC=0x{:02x} ISS=0x{:06x} PC=0x{:x} FAR=0x{:x}",
                            self.id, ec, iss, pc, far
                        );
                        Ok(VcpuExit::Exception)
                    }
                }
            }

            _ => Ok(VcpuExit::InternalError),
        }
    }

    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
        let mmio_state = self.last_mmio.lock().take();
        let mmio = mmio_state.ok_or_else(|| Error::new(libc::EINVAL))?;

        if mmio.is_write {
            let data = mmio.data.to_le_bytes();
            let write_data = &data[..mmio.size];
            handle_fn(IoParams {
                address: mmio.address,
                operation: IoOperation::Write(write_data),
            })?;
        } else {
            let mut data = [0u8; 8];
            let read_data = &mut data[..mmio.size];
            handle_fn(IoParams {
                address: mmio.address,
                operation: IoOperation::Read(read_data),
            })?;

            // Write the read value back to the register
            let value = match mmio.size {
                1 => data[0] as u64,
                2 => u16::from_le_bytes([data[0], data[1]]) as u64,
                4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64,
                8 => u64::from_le_bytes(data),
                _ => 0,
            };
            self.set_reg(mmio.reg_num, value)?;
        }

        // Advance PC past the faulting instruction
        self.advance_pc()?;

        Ok(())
    }

    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
        // AArch64 doesn't have PIO
        Err(Error::new(libc::ENOTSUP))
    }

    fn on_suspend(&self) -> Result<()> {
        Ok(())
    }

    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        Err(Error::new(libc::ENOTSUP))
    }
}

impl VcpuAArch64 for HvfVcpu {
    fn init(&self, _features: &[VcpuFeature]) -> Result<()> {
        // HVF VCPUs are initialized at creation time
        // Set up default state for the VCPU

        // Start in EL1h mode (SPSel=1, EL1)
        self.set_reg(bindings::HV_REG_CPSR, 0x3c5)?;

        // Enable floating point (CPACR_EL1.FPEN = 0b11)
        self.set_sys_reg(bindings::HV_SYS_REG_CPACR_EL1, 3 << 20)?;

        // Set MPIDR_EL1 to match the VCPU ID. This is required for HVF's
        // in-kernel GICv3 redistributor matching.
        self.set_sys_reg(bindings::HV_SYS_REG_MPIDR_EL1, self.id as u64)?;

        Ok(())
    }

    fn init_pmu(&self, _irq: u64) -> Result<()> {
        // HVF doesn't support in-kernel PMU virtualization
        Err(Error::new(libc::ENOTSUP))
    }

    fn has_pvtime_support(&self) -> bool {
        false
    }

    fn init_pvtime(&self, _pvtime_ipa: u64) -> Result<()> {
        Err(Error::new(libc::ENOTSUP))
    }

    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()> {
        match self.reg_to_hvf(reg_id) {
            Some(HvfRegType::Gpr(reg)) => self.set_reg(reg, data),
            Some(HvfRegType::SysReg(reg)) => self.set_sys_reg(reg, data),
            None => Err(Error::new(libc::EINVAL)),
        }
    }

    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64> {
        match self.reg_to_hvf(reg_id) {
            Some(HvfRegType::Gpr(reg)) => self.get_reg(reg),
            Some(HvfRegType::SysReg(reg)) => self.get_sys_reg(reg),
            None => Err(Error::new(libc::EINVAL)),
        }
    }

    fn set_vector_reg(&self, reg_num: u8, data: u128) -> Result<()> {
        if reg_num > 31 {
            return Err(Error::new(libc::EINVAL));
        }
        let value = bindings::hv_simd_fp_uchar16_t {
            bytes: data.to_le_bytes(),
        };
        // SAFETY: vcpu is valid and reg_num is in range
        let ret = unsafe {
            bindings::hv_vcpu_set_simd_fp_reg(
                self.vcpu,
                bindings::HV_SIMD_FP_REG_Q0 + reg_num as u32,
                value,
            )
        };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(())
    }

    fn get_vector_reg(&self, reg_num: u8) -> Result<u128> {
        if reg_num > 31 {
            return Err(Error::new(libc::EINVAL));
        }
        let mut value = bindings::hv_simd_fp_uchar16_t::default();
        // SAFETY: vcpu is valid and reg_num is in range
        let ret = unsafe {
            bindings::hv_vcpu_get_simd_fp_reg(
                self.vcpu,
                bindings::HV_SIMD_FP_REG_Q0 + reg_num as u32,
                &mut value,
            )
        };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::EIO));
        }
        Ok(u128::from_le_bytes(value.bytes))
    }

    fn get_system_regs(&self) -> Result<BTreeMap<AArch64SysRegId, u64>> {
        let mut regs = BTreeMap::new();

        // Read common system registers
        let sys_regs = [
            (bindings::HV_SYS_REG_SCTLR_EL1, "SCTLR_EL1"),
            (bindings::HV_SYS_REG_CPACR_EL1, "CPACR_EL1"),
            (bindings::HV_SYS_REG_TTBR0_EL1, "TTBR0_EL1"),
            (bindings::HV_SYS_REG_TTBR1_EL1, "TTBR1_EL1"),
            (bindings::HV_SYS_REG_TCR_EL1, "TCR_EL1"),
            (bindings::HV_SYS_REG_ESR_EL1, "ESR_EL1"),
            (bindings::HV_SYS_REG_FAR_EL1, "FAR_EL1"),
            (bindings::HV_SYS_REG_MAIR_EL1, "MAIR_EL1"),
            (bindings::HV_SYS_REG_VBAR_EL1, "VBAR_EL1"),
            (bindings::HV_SYS_REG_ELR_EL1, "ELR_EL1"),
            (bindings::HV_SYS_REG_SPSR_EL1, "SPSR_EL1"),
            (bindings::HV_SYS_REG_SP_EL0, "SP_EL0"),
            (bindings::HV_SYS_REG_SP_EL1, "SP_EL1"),
            (bindings::HV_SYS_REG_TPIDR_EL0, "TPIDR_EL0"),
            (bindings::HV_SYS_REG_TPIDR_EL1, "TPIDR_EL1"),
            (bindings::HV_SYS_REG_TPIDRRO_EL0, "TPIDRRO_EL0"),
            (bindings::HV_SYS_REG_MIDR_EL1, "MIDR_EL1"),
            (bindings::HV_SYS_REG_MPIDR_EL1, "MPIDR_EL1"),
        ];

        for (hvf_reg, _name) in &sys_regs {
            if let Ok(value) = self.get_sys_reg(*hvf_reg) {
                let id = AArch64SysRegId::from_encoded(*hvf_reg);
                regs.insert(id, value);
            }
        }

        Ok(regs)
    }

    fn hypervisor_specific_snapshot(&self) -> anyhow::Result<AnySnapshot> {
        // Snapshot HVF-specific state as an empty map for now
        AnySnapshot::to_any(&BTreeMap::<String, u64>::new())
    }

    fn hypervisor_specific_restore(&self, _data: AnySnapshot) -> anyhow::Result<()> {
        // Restore HVF-specific state (no-op for now)
        Ok(())
    }

    fn get_mpidr(&self) -> Result<u64> {
        self.get_sys_reg(bindings::HV_SYS_REG_MPIDR_EL1)
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        Ok(PsciVersion {
            major: 1,
            minor: 0,
        })
    }

    fn set_guest_debug(
        &self,
        _addrs: &[GuestAddress],
        _enable_singlestep: bool,
    ) -> Result<()> {
        // HVF supports debug traps but the API is different
        // For now, enable debug exception trapping
        // SAFETY: vcpu is valid
        unsafe {
            bindings::hv_vcpu_set_trap_debug_exceptions(self.vcpu, true);
        }
        Ok(())
    }

    fn get_max_hw_bps(&self) -> Result<usize> {
        // Apple Silicon supports at least 6 hardware breakpoints
        Ok(6)
    }

    fn get_cache_info(&self) -> Result<BTreeMap<u8, u64>> {
        Ok(BTreeMap::new())
    }

    fn set_cache_info(&self, _cache_info: BTreeMap<u8, u64>) -> Result<()> {
        Ok(())
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        // SAFETY: We created this vcpu
        unsafe {
            bindings::hv_vcpu_destroy(self.vcpu);
        }
    }
}
