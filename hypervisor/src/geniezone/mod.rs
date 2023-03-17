// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod geniezone_sys;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::convert::TryFrom;
use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::os::raw::c_int;
use std::os::raw::c_ulong;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use base::errno_result;
use base::error;
use base::ioctl;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::pagesize;
use base::sys::BlockedSignal;
use base::AsRawDescriptor;
use base::Error;
use base::Event;
use base::FromRawDescriptor;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MmapError;
use base::Protection;
use base::RawDescriptor;
use base::Result;
use base::SafeDescriptor;
use cros_fdt::FdtWriter;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::reg::id::AArch64RegId;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
pub use geniezone_sys::*;
use libc::open;
use libc::EBUSY;
use libc::EFAULT;
use libc::EINVAL;
use libc::EIO;
use libc::ENOENT;
use libc::ENOMEM;
use libc::ENOSPC;
use libc::ENOTSUP;
use libc::EOVERFLOW;
use libc::O_CLOEXEC;
use libc::O_RDWR;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegionInformation;

use crate::ClockState;
use crate::Config;
use crate::Datamatch;
use crate::DeviceKind;
use crate::HypervHypercall;
use crate::Hypervisor;
use crate::HypervisorCap;
use crate::IoEventAddress;
use crate::IoOperation;
use crate::IoParams;
use crate::MemSlot;
use crate::PsciVersion;
use crate::Vcpu;
use crate::VcpuAArch64;
use crate::VcpuExit;
use crate::VcpuFeature;
use crate::VcpuRegAArch64;
use crate::VcpuRunHandle;
use crate::Vm;
use crate::VmAArch64;
use crate::VmCap;
use crate::PSCI_0_2;

impl Geniezone {
    /// Get the size of guest physical addresses (IPA) in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // Safe because we know self is a real geniezone fd
        match unsafe {
            ioctl_with_val(
                self,
                GZVM_CHECK_EXTENSION(),
                GZVM_CAP_ARM_VM_IPA_SIZE.into(),
            )
        } {
            // Default physical address size is 40 bits if the extension is not supported.
            ret if ret <= 0 => 40,
            ipa => ipa as u8,
        }
    }
}

impl GeniezoneVm {
    /// Does platform specific initialization for the GeniezoneVm.
    pub fn init_arch(&self, cfg: &Config) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        if cfg.mte {
            // Safe because it does not take pointer arguments.
            unsafe {
                self.ctrl_geniezone_enable_capability(GeniezoneCap::ArmMte, &[0, 0, 0, 0, 0])
            }?;
        }
        Ok(())
    }

    /// Checks if a particular `VmCap` is available, or returns None if arch-independent
    /// Vm.check_capability() should handle the check.
    pub fn check_capability_arch(&self, _c: VmCap) -> Option<bool> {
        None
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.  Always returns an error on AArch64.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        // TODO: Geniezone not support pvclock currently
        error!("Geniezone: not support get_pvclock_arch");
        Err(Error::new(EINVAL))
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.  Always returns an error on AArch64.
    pub fn set_pvclock_arch(&self, _state: &ClockState) -> Result<()> {
        // TODO: Geniezone not support pvclock currently
        error!("Geniezone: not support set_pvclock_arch");
        Err(Error::new(EINVAL))
    }

    fn get_protected_vm_info(&self) -> Result<u64> {
        // Safe because we allocated the struct and we know the kernel won't write beyond the end of
        // the struct or keep a pointer to it.
        let cap: gzvm_enable_cap = unsafe {
            self.ctrl_geniezone_enable_capability(
                GeniezoneCap::ArmProtectedVm,
                &[GZVM_CAP_ARM_PVM_GET_PVMFW_SIZE as u64, 0, 0, 0, 0],
            )
        }?;
        Ok(cap.args[1])
    }

    fn set_protected_vm_firmware_ipa(&self, fw_addr: GuestAddress) -> Result<()> {
        // Safe because none of the args are pointers.
        unsafe {
            self.ctrl_geniezone_enable_capability(
                GeniezoneCap::ArmProtectedVm,
                &[GZVM_CAP_ARM_PVM_SET_PVMFW_IPA as u64, fw_addr.0, 0, 0, 0],
            )
        }?;
        Ok(())
    }
}

impl VmAArch64 for GeniezoneVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.geniezone
    }

    fn load_protected_vm_firmware(
        &mut self,
        fw_addr: GuestAddress,
        fw_max_size: u64,
    ) -> Result<()> {
        let size: u64 = self.get_protected_vm_info()?;
        if size == 0 {
            Err(Error::new(EINVAL))
        } else {
            if size > fw_max_size {
                return Err(Error::new(ENOMEM));
            }
            self.set_protected_vm_firmware_ipa(fw_addr)
        }
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>> {
        Ok(Box::new(GeniezoneVm::create_vcpu(self, id)?))
    }

    fn create_fdt(
        &self,
        _fdt: &mut FdtWriter,
        _phandles: &BTreeMap<&str, u32>,
    ) -> cros_fdt::Result<()> {
        Ok(())
    }
}

impl GeniezoneVcpu {
    /// Arch-specific implementation of `Vcpu::pvclock_ctrl`.  Always returns an error on AArch64.
    pub fn pvclock_ctrl_arch(&self) -> Result<()> {
        Err(Error::new(EINVAL))
    }

    fn set_one_geniezone_reg_u64(
        &self,
        gzvm_reg_id: GeniezoneVcpuRegister,
        data: u64,
    ) -> Result<()> {
        self.set_one_geniezone_reg(gzvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_geniezone_reg(&self, gzvm_reg_id: GeniezoneVcpuRegister, data: &[u8]) -> Result<()> {
        let onereg = gzvm_one_reg {
            id: gzvm_reg_id.into(),
            addr: (data.as_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, GZVM_SET_ONE_REG(), &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_one_geniezone_reg_u64(&self, gzvm_reg_id: GeniezoneVcpuRegister) -> Result<u64> {
        let mut bytes = 0u64.to_ne_bytes();
        self.get_one_geniezone_reg(gzvm_reg_id, bytes.as_mut_slice())?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn get_one_geniezone_reg(
        &self,
        gzvm_reg_id: GeniezoneVcpuRegister,
        data: &mut [u8],
    ) -> Result<()> {
        let onereg = gzvm_one_reg {
            id: gzvm_reg_id.into(),
            addr: (data.as_mut_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, GZVM_GET_ONE_REG(), &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

#[allow(dead_code)]
/// GZVM registers as used by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API
pub enum GeniezoneVcpuRegister {
    /// General Purpose Registers X0-X30
    X(u8),
    /// Stack Pointer
    Sp,
    /// Program Counter
    Pc,
    /// Processor State
    Pstate,
    /// Stack Pointer (EL1)
    SpEl1,
    /// Exception Link Register (EL1)
    ElrEl1,
    /// Saved Program Status Register (EL1, abt, und, irq, fiq)
    Spsr(u8),
    /// FP & SIMD Registers V0-V31
    V(u8),
    /// Floating-point Status Register
    Fpsr,
    /// Floating-point Control Register
    Fpcr,
    /// Geniezone Firmware Pseudo-Registers
    Firmware(u16),
    /// Generic System Registers by (Op0, Op1, CRn, CRm, Op2)
    System(u16),
    /// CCSIDR_EL1 Demultiplexed by CSSELR_EL1
    Ccsidr(u8),
}

/// Gives the `u64` register ID expected by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API.
impl From<GeniezoneVcpuRegister> for u64 {
    fn from(register: GeniezoneVcpuRegister) -> Self {
        const fn reg(size: u64, kind: u64, fields: u64) -> u64 {
            GZVM_REG_ARM64 | size | kind | fields
        }

        const fn gzvm_regs_reg(size: u64, offset: usize) -> u64 {
            let offset = offset / std::mem::size_of::<u32>();

            reg(size, GZVM_REG_ARM_CORE as u64, offset as u64)
        }

        const fn gzvm_reg(offset: usize) -> u64 {
            gzvm_regs_reg(GZVM_REG_SIZE_U64, offset)
        }

        fn user_pt_reg(offset: usize) -> u64 {
            gzvm_regs_reg(
                GZVM_REG_SIZE_U64,
                memoffset::offset_of!(gzvm_regs, regs) + offset,
            )
        }

        fn user_fpsimd_state_reg(size: u64, offset: usize) -> u64 {
            gzvm_regs_reg(size, memoffset::offset_of!(gzvm_regs, fp_regs) + offset)
        }

        const fn reg_u64(kind: u64, fields: u64) -> u64 {
            reg(GZVM_REG_SIZE_U64, kind, fields)
        }

        const fn demux_reg(size: u64, index: u64, value: u64) -> u64 {
            let index =
                (index << GZVM_REG_ARM_DEMUX_ID_SHIFT) & (GZVM_REG_ARM_DEMUX_ID_MASK as u64);
            let value =
                (value << GZVM_REG_ARM_DEMUX_VAL_SHIFT) & (GZVM_REG_ARM_DEMUX_VAL_MASK as u64);

            reg(size, GZVM_REG_ARM_DEMUX as u64, index | value)
        }

        match register {
            GeniezoneVcpuRegister::X(n @ 0..=30) => {
                let n = std::mem::size_of::<u64>() * (n as usize);

                user_pt_reg(memoffset::offset_of!(user_pt_regs, regs) + n)
            }
            GeniezoneVcpuRegister::X(n) => {
                unreachable!("invalid GeniezoneVcpuRegister Xn index: {n}")
            }
            GeniezoneVcpuRegister::Sp => user_pt_reg(memoffset::offset_of!(user_pt_regs, sp)),
            GeniezoneVcpuRegister::Pc => user_pt_reg(memoffset::offset_of!(user_pt_regs, pc)),
            GeniezoneVcpuRegister::Pstate => {
                user_pt_reg(memoffset::offset_of!(user_pt_regs, pstate))
            }
            GeniezoneVcpuRegister::SpEl1 => gzvm_reg(memoffset::offset_of!(gzvm_regs, sp_el1)),
            GeniezoneVcpuRegister::ElrEl1 => gzvm_reg(memoffset::offset_of!(gzvm_regs, elr_el1)),
            GeniezoneVcpuRegister::Spsr(n @ 0..=4) => {
                let n = std::mem::size_of::<u64>() * (n as usize);
                gzvm_reg(memoffset::offset_of!(gzvm_regs, spsr) + n)
            }
            GeniezoneVcpuRegister::Spsr(n) => {
                unreachable!("invalid GeniezoneVcpuRegister Spsr index: {n}")
            }
            GeniezoneVcpuRegister::V(n @ 0..=31) => {
                let n = std::mem::size_of::<u128>() * (n as usize);
                user_fpsimd_state_reg(
                    GZVM_REG_SIZE_U128,
                    memoffset::offset_of!(user_fpsimd_state, vregs) + n,
                )
            }
            GeniezoneVcpuRegister::V(n) => {
                unreachable!("invalid GeniezoneVcpuRegister Vn index: {n}")
            }
            GeniezoneVcpuRegister::Fpsr => user_fpsimd_state_reg(
                GZVM_REG_SIZE_U32,
                memoffset::offset_of!(user_fpsimd_state, fpsr),
            ),
            GeniezoneVcpuRegister::Fpcr => user_fpsimd_state_reg(
                GZVM_REG_SIZE_U32,
                memoffset::offset_of!(user_fpsimd_state, fpcr),
            ),
            GeniezoneVcpuRegister::Firmware(n) => reg_u64(GZVM_REG_ARM, n.into()),
            GeniezoneVcpuRegister::System(n) => reg_u64(GZVM_REG_ARM64_SYSREG.into(), n.into()),
            GeniezoneVcpuRegister::Ccsidr(n) => demux_reg(GZVM_REG_SIZE_U32, 0, n.into()),
        }
    }
}

#[cfg(feature = "gdb")]
impl TryFrom<AArch64RegId> for GeniezoneVcpuRegister {
    type Error = Error;

    fn try_from(_reg: <GdbArch as Arch>::RegId) -> std::result::Result<Self, Self::Error> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support gdb");
        Err(Error::new(EINVAL))
    }
}

impl From<VcpuRegAArch64> for GeniezoneVcpuRegister {
    fn from(reg: VcpuRegAArch64) -> Self {
        match reg {
            VcpuRegAArch64::X(n @ 0..=30) => Self::X(n),
            VcpuRegAArch64::X(n) => unreachable!("invalid VcpuRegAArch64 index: {n}"),
            VcpuRegAArch64::Sp => Self::Sp,
            VcpuRegAArch64::Pc => Self::Pc,
            VcpuRegAArch64::Pstate => Self::Pstate,
        }
    }
}

impl VcpuAArch64 for GeniezoneVcpu {
    fn init(&self, _features: &[VcpuFeature]) -> Result<()> {
        // Geniezone init vcpu in creation
        // Return Ok since aarch64/src/lib.rs will use this
        Ok(())
    }

    fn init_pmu(&self, _irq: u64) -> Result<()> {
        // TODO: Geniezone not support pmu currently
        // temporary return ok since aarch64/src/lib.rs will use this
        Ok(())
    }

    fn has_pvtime_support(&self) -> bool {
        // TODO: Geniezone not support pvtime currently
        false
    }

    fn init_pvtime(&self, _pvtime_ipa: u64) -> Result<()> {
        // TODO: Geniezone not support pvtime currently
        error!("Geniezone: not support init_pvtime");
        Err(Error::new(EINVAL))
    }

    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()> {
        self.set_one_geniezone_reg_u64(GeniezoneVcpuRegister::from(reg_id), data)
    }

    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64> {
        self.get_one_geniezone_reg_u64(GeniezoneVcpuRegister::from(reg_id))
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        Ok(PSCI_0_2)
    }

    #[cfg(feature = "gdb")]
    fn get_max_hw_bps(&self) -> Result<usize> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support get_max_hw_bps");
        Err(Error::new(EINVAL))
    }

    #[cfg(feature = "gdb")]
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support set_gdb_registers");
        Err(Error::new(EINVAL))
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_registers(&self, _regs: &<GdbArch as Arch>::Registers) -> Result<()> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support set_gdb_registers");
        Err(Error::new(EINVAL))
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_registers(&self, _regs: &mut <GdbArch as Arch>::Registers) -> Result<()> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support get_gdb_registers");
        Err(Error::new(EINVAL))
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_register(&self, _reg: <GdbArch as Arch>::RegId, _data: &[u8]) -> Result<()> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support set_gdb_register");
        Err(Error::new(EINVAL))
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_register(&self, _reg: <GdbArch as Arch>::RegId, _data: &mut [u8]) -> Result<usize> {
        // TODO: Geniezone not support gdb currently
        error!("Geniezone: not support get_gdb_register");
        Err(Error::new(EINVAL))
    }
}

// Wrapper around GZVM_SET_USER_MEMORY_REGION ioctl, which creates, modifies, or deletes a mapping
// from guest physical to host user pages.
//
// Safe when the guest regions are guaranteed not to overlap.
unsafe fn set_user_memory_region(
    descriptor: &SafeDescriptor,
    slot: MemSlot,
    _read_only: bool,
    _log_dirty_pages: bool,
    guest_addr: u64,
    memory_size: u64,
    userspace_addr: *mut u8,
) -> Result<()> {
    let flags = 0;
    let region = gzvm_userspace_memory_region {
        slot,
        flags,
        guest_phys_addr: guest_addr,
        memory_size,
        userspace_addr: userspace_addr as u64,
    };

    let ret = ioctl_with_ref(descriptor, GZVM_SET_USER_MEMORY_REGION(), &region);
    if ret == 0 {
        Ok(())
    } else {
        errno_result()
    }
}

/// Helper function to determine the size in bytes of a dirty log bitmap for the given memory region
/// size.
///
/// # Arguments
///
/// * `size` - Number of bytes in the memory region being queried.
pub fn dirty_log_bitmap_size(size: usize) -> usize {
    let page_size = pagesize();
    (((size + page_size - 1) / page_size) + 7) / 8
}

pub struct Geniezone {
    geniezone: SafeDescriptor,
}

#[repr(u32)]
pub enum GeniezoneCap {
    ArmMte,
    ArmProtectedVm = GZVM_CAP_ARM_PROTECTED_VM,
}

impl Geniezone {
    pub fn new_with_path(device_path: &Path) -> Result<Geniezone> {
        // Open calls are safe because we give a nul-terminated string and verify the result.
        let c_path = CString::new(device_path.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { open(c_path.as_ptr(), O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        // Safe because we verify that ret is valid and we own the fd.
        Ok(Geniezone {
            geniezone: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
        })
    }

    /// Opens `/dev/gzvm/` and returns a gzvm object on success.
    pub fn new() -> Result<Geniezone> {
        Geniezone::new_with_path(&PathBuf::from("/dev/gzvm"))
    }

    /// Gets the size of the mmap required to use vcpu's `gzvm_vcpu_run` structure.
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // We don't use mmap, return sizeof(gzvm_vcpu_run) directly
        let res = std::mem::size_of::<gzvm_vcpu_run>() as usize;
        Ok(res)
    }
}

impl AsRawDescriptor for Geniezone {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.geniezone.as_raw_descriptor()
    }
}

impl Hypervisor for Geniezone {
    fn try_clone(&self) -> Result<Self> {
        Ok(Geniezone {
            geniezone: self.geniezone.try_clone()?,
        })
    }

    fn check_capability(&self, cap: HypervisorCap) -> bool {
        matches!(
            cap,
            HypervisorCap::UserMemory | HypervisorCap::ImmediateExit
        )
    }
}

/// A wrapper around creating and using a Geniezone VM.
pub struct GeniezoneVm {
    geniezone: Geniezone,
    vm: SafeDescriptor,
    guest_mem: GuestMemory,
    mem_regions: Arc<Mutex<BTreeMap<MemSlot, Box<dyn MappedRegion>>>>,
    /// A min heap of MemSlot numbers that were used and then removed and can now be re-used
    mem_slot_gaps: Arc<Mutex<BinaryHeap<Reverse<MemSlot>>>>,
}

impl GeniezoneVm {
    /// Constructs a new `GeniezoneVm` using the given `Geniezone` instance.
    pub fn new(geniezone: &Geniezone, guest_mem: GuestMemory, cfg: Config) -> Result<GeniezoneVm> {
        // Safe because we know gzvm is a real gzvm fd as this module is the only one that can make
        // gzvm objects.
        let ret = unsafe { ioctl(geniezone, GZVM_CREATE_VM()) };
        if ret < 0 {
            return errno_result();
        }
        // Safe because we verify that ret is valid and we own the fd.
        let vm_descriptor = unsafe { SafeDescriptor::from_raw_descriptor(ret) };
        guest_mem.with_regions(
            |MemoryRegionInformation {
                 index,
                 guest_addr,
                 size,
                 host_addr,
                 ..
             }| {
                unsafe {
                    // Safe because the guest regions are guaranteed not to overlap.
                    set_user_memory_region(
                        &vm_descriptor,
                        index as MemSlot,
                        false,
                        false,
                        guest_addr.offset(),
                        size as u64,
                        host_addr as *mut u8,
                    )
                }
            },
        )?;

        let vm = GeniezoneVm {
            geniezone: geniezone.try_clone()?,
            vm: vm_descriptor,
            guest_mem,
            mem_regions: Arc::new(Mutex::new(BTreeMap::new())),
            mem_slot_gaps: Arc::new(Mutex::new(BinaryHeap::new())),
        };
        vm.init_arch(&cfg)?;
        Ok(vm)
    }

    fn create_vcpu(&self, id: usize) -> Result<GeniezoneVcpu> {
        // run is a data stucture shared with ko and geniezone
        let run_mmap_size = self.geniezone.get_vcpu_mmap_size()?;

        // Safe because we know that our file is a VM fd and we verify the return result.
        let fd =
            unsafe { ioctl_with_val(self, GZVM_CREATE_VCPU(), c_ulong::try_from(id).unwrap()) };

        if fd < 0 {
            return errno_result();
        }

        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { SafeDescriptor::from_raw_descriptor(fd) };

        // Memory mapping --> Memory allocation
        let run_mmap = MemoryMappingBuilder::new(run_mmap_size)
            .build()
            .map_err(|_| Error::new(ENOSPC))?;

        Ok(GeniezoneVcpu {
            vm: self.vm.try_clone()?,
            vcpu,
            id,
            run_mmap,
            vcpu_run_handle_fingerprint: Default::default(),
        })
    }

    /// Creates an in kernel interrupt controller.
    ///
    /// See the documentation on the GZVM_CREATE_IRQCHIP ioctl.
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, GZVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        let mut irq_level = gzvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = active as u32;

        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, GZVM_IRQ_LINE(), &irq_level) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Registers an event that will, when signalled, trigger the `gsi` irq, and `resample_evt`
    /// ( when not None ) will be triggered when the irqchip is resampled.
    pub fn register_irqfd(
        &self,
        gsi: u32,
        evt: &Event,
        resample_evt: Option<&Event>,
    ) -> Result<()> {
        let mut irqfd = gzvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            ..Default::default()
        };

        if let Some(r_evt) = resample_evt {
            irqfd.flags = GZVM_IRQFD_FLAG_RESAMPLE;
            irqfd.resamplefd = r_evt.as_raw_descriptor() as u32;
        }

        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, GZVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Unregisters an event that was previously registered with
    /// `register_irqfd`.
    ///
    /// The `evt` and `gsi` pair must be the same as the ones passed into
    /// `register_irqfd`.
    pub fn unregister_irqfd(&self, gsi: u32, evt: &Event) -> Result<()> {
        let irqfd = gzvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            flags: GZVM_IRQFD_FLAG_DEASSIGN,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, GZVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn ioeventfd(
        &self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
        deassign: bool,
    ) -> Result<()> {
        let (do_datamatch, datamatch_value, datamatch_len) = match datamatch {
            Datamatch::AnyLength => (false, 0, 0),
            Datamatch::U8(v) => match v {
                Some(u) => (true, u as u64, 1),
                None => (false, 0, 1),
            },
            Datamatch::U16(v) => match v {
                Some(u) => (true, u as u64, 2),
                None => (false, 0, 2),
            },
            Datamatch::U32(v) => match v {
                Some(u) => (true, u as u64, 4),
                None => (false, 0, 4),
            },
            Datamatch::U64(v) => match v {
                Some(u) => (true, u as u64, 8),
                None => (false, 0, 8),
            },
        };
        let mut flags = 0;
        if deassign {
            flags |= 1 << gzvm_ioeventfd_flag_nr_deassign;
        }
        if do_datamatch {
            flags |= 1 << gzvm_ioeventfd_flag_nr_datamatch
        }
        if let IoEventAddress::Pio(_) = addr {
            flags |= 1 << gzvm_ioeventfd_flag_nr_pio;
        }
        let ioeventfd = gzvm_ioeventfd {
            datamatch: datamatch_value,
            len: datamatch_len,
            addr: match addr {
                IoEventAddress::Pio(p) => p as u64,
                IoEventAddress::Mmio(m) => m,
            },
            fd: evt.as_raw_descriptor(),
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, GZVM_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Checks whether a particular GZVM-specific capability is available for this VM.
    fn check_raw_capability(&self, capability: GeniezoneCap) -> bool {
        // Safe because we know that our file is a GZVM fd, and if the cap is invalid GZVM assumes
        // it's an unavailable extension and returns 0.
        let cap: u64 = capability as u64;
        unsafe {
            ioctl_with_ref(self, GZVM_CHECK_EXTENSION(), &cap);
        }
        cap == 1
    }

    // Currently only used on aarch64, but works on any architecture.
    #[allow(dead_code)]
    /// Enables a GZVM-specific capability for this VM, with the given arguments.
    ///
    /// # Safety
    /// This function is marked as unsafe because `args` may be interpreted as pointers for some
    /// capabilities. The caller must ensure that any pointers passed in the `args` array are
    /// allocated as the kernel expects, and that mutable pointers are owned.
    unsafe fn ctrl_geniezone_enable_capability(
        &self,
        capability: GeniezoneCap,
        args: &[u64; 5],
    ) -> Result<gzvm_enable_cap> {
        let gzvm_cap = gzvm_enable_cap {
            cap: capability as u64,
            args: *args,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct, and because we assume the caller has allocated the args appropriately.
        let ret = ioctl_with_ref(self, GZVM_ENABLE_CAP(), &gzvm_cap);
        if ret == 0 {
            Ok(gzvm_cap)
        } else {
            errno_result()
        }
    }

    pub fn create_geniezone_device(&self, dev: gzvm_create_device) -> Result<()> {
        let ret = unsafe { base::ioctl_with_ref(self, GZVM_CREATE_DEVICE(), &dev) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl Vm for GeniezoneVm {
    fn try_clone(&self) -> Result<Self> {
        Ok(GeniezoneVm {
            geniezone: self.geniezone.try_clone()?,
            vm: self.vm.try_clone()?,
            guest_mem: self.guest_mem.clone(),
            mem_regions: self.mem_regions.clone(),
            mem_slot_gaps: self.mem_slot_gaps.clone(),
        })
    }

    fn check_capability(&self, c: VmCap) -> bool {
        if let Some(val) = self.check_capability_arch(c) {
            return val;
        }
        match c {
            VmCap::DirtyLog => true,
            VmCap::PvClock => false,
            VmCap::PvClockSuspend => false,
            VmCap::Protected => self.check_raw_capability(GeniezoneCap::ArmProtectedVm),
            VmCap::EarlyInitCpuid => false,
        }
    }

    fn get_guest_phys_addr_bits(&self) -> u8 {
        self.geniezone.get_guest_phys_addr_bits()
    }

    fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    fn add_memory_region(
        &mut self,
        guest_addr: GuestAddress,
        mem: Box<dyn MappedRegion>,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<MemSlot> {
        let pgsz = pagesize() as u64;
        // GZVM require to set the user memory region with page size aligned size. Safe to extend
        // the mem.size() to be page size aligned because the mmap will round up the size to be
        // page size aligned if it is not.
        let size = (mem.size() as u64 + pgsz - 1) / pgsz * pgsz;
        let end_addr = guest_addr
            .checked_add(size)
            .ok_or_else(|| Error::new(EOVERFLOW))?;
        if self.guest_mem.range_overlap(guest_addr, end_addr) {
            return Err(Error::new(ENOSPC));
        }
        let mut regions = self.mem_regions.lock();
        let mut gaps = self.mem_slot_gaps.lock();
        let slot = match gaps.pop() {
            Some(gap) => gap.0,
            None => (regions.len() + self.guest_mem.num_regions() as usize) as MemSlot,
        };

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        let res = unsafe {
            set_user_memory_region(
                &self.vm,
                slot,
                read_only,
                log_dirty_pages,
                guest_addr.offset() as u64,
                size,
                mem.as_ptr(),
            )
        };

        if let Err(e) = res {
            gaps.push(Reverse(slot));
            return Err(e);
        }
        regions.insert(slot, mem);
        Ok(slot)
    }

    fn msync_memory_region(&mut self, slot: MemSlot, offset: usize, size: usize) -> Result<()> {
        let mut regions = self.mem_regions.lock();
        let mem = regions.get_mut(&slot).ok_or_else(|| Error::new(ENOENT))?;

        mem.msync(offset, size).map_err(|err| match err {
            MmapError::InvalidAddress => Error::new(EFAULT),
            MmapError::NotPageAligned => Error::new(EINVAL),
            MmapError::SystemCallFailed(e) => e,
            _ => Error::new(EIO),
        })
    }

    fn remove_memory_region(&mut self, slot: MemSlot) -> Result<Box<dyn MappedRegion>> {
        let mut regions = self.mem_regions.lock();
        if !regions.contains_key(&slot) {
            return Err(Error::new(ENOENT));
        }
        // Safe because the slot is checked against the list of memory slots.
        unsafe {
            set_user_memory_region(&self.vm, slot, false, false, 0, 0, std::ptr::null_mut())?;
        }
        self.mem_slot_gaps.lock().push(Reverse(slot));
        // This remove will always succeed because of the contains_key check above.
        Ok(regions.remove(&slot).unwrap())
    }

    fn create_device(&self, _kind: DeviceKind) -> Result<SafeDescriptor> {
        // This function should not be invoked because the vgic device is created in irqchip.
        errno_result()
    }

    fn get_dirty_log(&self, _slot: MemSlot, _dirty_log: &mut [u8]) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    fn register_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, false)
    }

    fn unregister_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, true)
    }

    fn handle_io_events(&self, _addr: IoEventAddress, _data: &[u8]) -> Result<()> {
        // GZVM delivers IO events in-kernel with ioeventfds, so this is a no-op
        Ok(())
    }

    fn get_pvclock(&self) -> Result<ClockState> {
        self.get_pvclock_arch()
    }

    fn set_pvclock(&self, state: &ClockState) -> Result<()> {
        self.set_pvclock_arch(state)
    }

    fn add_fd_mapping(
        &mut self,
        slot: u32,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<()> {
        let mut regions = self.mem_regions.lock();
        let region = regions.get_mut(&slot).ok_or_else(|| Error::new(EINVAL))?;

        match region.add_fd_mapping(offset, size, fd, fd_offset, prot) {
            Ok(()) => Ok(()),
            Err(MmapError::SystemCallFailed(e)) => Err(e),
            Err(_) => Err(Error::new(EIO)),
        }
    }

    fn remove_mapping(&mut self, slot: u32, offset: usize, size: usize) -> Result<()> {
        let mut regions = self.mem_regions.lock();
        let region = regions.get_mut(&slot).ok_or_else(|| Error::new(EINVAL))?;

        match region.remove_mapping(offset, size) {
            Ok(()) => Ok(()),
            Err(MmapError::SystemCallFailed(e)) => Err(e),
            Err(_) => Err(Error::new(EIO)),
        }
    }

    fn handle_inflate(&mut self, guest_address: GuestAddress, size: u64) -> Result<()> {
        match self.guest_mem.remove_range(guest_address, size) {
            Ok(_) => Ok(()),
            Err(vm_memory::Error::MemoryAccess(_, MmapError::SystemCallFailed(e))) => Err(e),
            Err(_) => Err(Error::new(EIO)),
        }
    }

    fn handle_deflate(&mut self, _guest_address: GuestAddress, _size: u64) -> Result<()> {
        // No-op, when the guest attempts to access the pages again, Linux/GZVM will provide them.
        Ok(())
    }
}

impl AsRawDescriptor for GeniezoneVm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vm.as_raw_descriptor()
    }
}

/// A wrapper around using a Geniezone Vcpu.
pub struct GeniezoneVcpu {
    vm: SafeDescriptor,
    vcpu: SafeDescriptor,
    id: usize,
    run_mmap: MemoryMapping,
    vcpu_run_handle_fingerprint: Arc<AtomicU64>,
}

pub(super) struct VcpuThread {
    run: *mut gzvm_vcpu_run,
    signal_num: Option<c_int>,
}

thread_local!(static VCPU_THREAD: RefCell<Option<VcpuThread>> = RefCell::new(None));

impl Vcpu for GeniezoneVcpu {
    fn try_clone(&self) -> Result<Self> {
        let vm = self.vm.try_clone()?;
        let vcpu = self.vcpu.try_clone()?;
        let run_mmap = MemoryMappingBuilder::new(self.run_mmap.size())
            .build()
            .map_err(|_| Error::new(ENOSPC))?;

        let vcpu_run_handle_fingerprint = self.vcpu_run_handle_fingerprint.clone();

        Ok(GeniezoneVcpu {
            vm,
            vcpu,
            id: self.id,
            run_mmap,
            vcpu_run_handle_fingerprint,
        })
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn take_run_handle(&self, signal_num: Option<c_int>) -> Result<VcpuRunHandle> {
        fn vcpu_run_handle_drop() {
            VCPU_THREAD.with(|v| {
                // This assumes that a failure in `BlockedSignal::new` means the signal is already
                // blocked and there it should not be unblocked on exit.
                let _blocked_signal = &(*v.borrow())
                    .as_ref()
                    .and_then(|state| state.signal_num)
                    .map(BlockedSignal::new);

                *v.borrow_mut() = None;
            });
        }

        // Prevent `vcpu_run_handle_drop` from being called until we actually setup the signal
        // blocking. The handle needs to be made now so that we can use the fingerprint.
        let vcpu_run_handle = ManuallyDrop::new(VcpuRunHandle::new(vcpu_run_handle_drop));

        // AcqRel ordering is sufficient to ensure only one thread gets to set its fingerprint to
        // this Vcpu and subsequent `run` calls will see the fingerprint.
        if self
            .vcpu_run_handle_fingerprint
            .compare_exchange(
                0,
                vcpu_run_handle.fingerprint().as_u64(),
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return Err(Error::new(EBUSY));
        }

        // Block signal while we add -- if a signal fires (very unlikely,
        // as this means something is trying to pause the vcpu before it has
        // even started) it'll try to grab the read lock while this write
        // lock is grabbed and cause a deadlock.
        // Assuming that a failure to block means it's already blocked.
        let _blocked_signal = signal_num.map(BlockedSignal::new);

        VCPU_THREAD.with(|v| {
            if v.borrow().is_none() {
                *v.borrow_mut() = Some(VcpuThread {
                    run: self.run_mmap.as_ptr() as *mut gzvm_vcpu_run,
                    signal_num,
                });
                Ok(())
            } else {
                Err(Error::new(EBUSY))
            }
        })?;

        Ok(ManuallyDrop::into_inner(vcpu_run_handle))
    }

    fn id(&self) -> usize {
        self.id
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn set_immediate_exit(&self, exit: bool) {
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut gzvm_vcpu_run) };
        run.immediate_exit = exit as u8;
    }

    fn set_local_immediate_exit(exit: bool) {
        VCPU_THREAD.with(|v| {
            if let Some(state) = &(*v.borrow()) {
                unsafe {
                    (*state.run).immediate_exit = exit as u8;
                };
            }
        });
    }

    fn set_local_immediate_exit_fn(&self) -> extern "C" fn() {
        extern "C" fn f() {
            GeniezoneVcpu::set_local_immediate_exit(true);
        }
        f
    }

    fn pvclock_ctrl(&self) -> Result<()> {
        Err(Error::new(libc::ENXIO))
    }

    fn set_signal_mask(&self, _signals: &[c_int]) -> Result<()> {
        Err(Error::new(libc::ENXIO))
    }

    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        Err(Error::new(libc::ENXIO))
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
        let ret = unsafe { ioctl_with_val(self, GZVM_RUN(), self.run_mmap.as_ptr() as u64) };
        if ret != 0 {
            return errno_result();
        }

        // Safe because we know we mapped enough memory to hold the gzvm_vcpu_run struct because the
        // kernel told us how large it was.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut gzvm_vcpu_run) };

        match run.exit_reason {
            GZVM_EXIT_MMIO => Ok(VcpuExit::Mmio),
            GZVM_EXIT_IRQ => Ok(VcpuExit::IrqWindowOpen),
            GZVM_EXIT_HVC => Ok(VcpuExit::Hypercall),
            GZVM_EXIT_EXCEPTION => Err(Error::new(EINVAL)),
            GZVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
            GZVM_EXIT_FAIL_ENTRY => {
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let hardware_entry_failure_reason = unsafe {
                    run.__bindgen_anon_1
                        .fail_entry
                        .hardware_entry_failure_reason
                };
                Ok(VcpuExit::FailEntry {
                    hardware_entry_failure_reason,
                })
            }
            GZVM_EXIT_SYSTEM_EVENT => {
                let event_type = unsafe { run.__bindgen_anon_1.system_event.type_ };
                match event_type {
                    GZVM_SYSTEM_EVENT_SHUTDOWN => Ok(VcpuExit::SystemEventShutdown),
                    GZVM_SYSTEM_EVENT_RESET => Ok(VcpuExit::SystemEventReset),
                    GZVM_SYSTEM_EVENT_CRASH => Ok(VcpuExit::SystemEventCrash),
                    GZVM_SYSTEM_EVENT_S2IDLE => Ok(VcpuExit::SystemEventS2Idle),
                    _ => {
                        error!("Unknown GZVM system event {}", event_type);
                        Err(Error::new(EINVAL))
                    }
                }
            }
            GZVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
            GZVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
            GZVM_EXIT_UNKNOWN => panic!("unknown gzvm exit reason\n"),
            r => panic!("unknown gzvm exit reason: {}", r),
        }
    }

    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        // Safe because we know we mapped enough memory to hold the gzvm_vcpu_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut gzvm_vcpu_run) };

        // Verify that the handler is called in the right context.
        assert!(run.exit_reason == GZVM_EXIT_MMIO);
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.

        let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
        let address = mmio.phys_addr;

        let size = mmio.size as usize;

        if mmio.is_write != 0 {
            handle_fn(IoParams {
                address,
                size,
                operation: IoOperation::Write { data: mmio.data },
            });
            Ok(())
        } else if let Some(data) = handle_fn(IoParams {
            address,
            size,
            operation: IoOperation::Read,
        }) {
            mmio.data[..size].copy_from_slice(&data[..size]);
            Ok(())
        } else {
            Err(Error::new(EINVAL))
        }
    }

    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        Err(Error::new(EINVAL))
    }

    fn handle_hyperv_hypercall(
        &self,
        _handle_fn: &mut dyn FnMut(HypervHypercall) -> u64,
    ) -> Result<()> {
        Err(Error::new(EINVAL))
    }

    fn handle_rdmsr(&self, _data: u64) -> Result<()> {
        Err(Error::new(EINVAL))
    }

    fn handle_wrmsr(&self) {}
}

impl AsRawDescriptor for GeniezoneVcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vcpu.as_raw_descriptor()
    }
}
