// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod halla_sys;

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::convert::TryFrom;
use std::ffi::CString;
use std::mem::offset_of;
use std::os::raw::c_ulong;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use aarch64_sys_reg::AArch64SysRegId;
use base::errno_result;
use base::error;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::pagesize;
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
use cros_fdt::Fdt;
pub use halla_sys::*;
use libc::open;
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
use snapshot::AnySnapshot;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegionPurpose;

use crate::BalloonEvent;
use crate::ClockState;
use crate::Config;
use crate::Datamatch;
use crate::DeviceKind;
use crate::Hypervisor;
use crate::HypervisorCap;
use crate::HypervisorKind;
use crate::IoEventAddress;
use crate::IoOperation;
use crate::IoParams;
use crate::MemCacheType;
use crate::MemSlot;
use crate::ProtectionType;
use crate::PsciVersion;
use crate::Vcpu;
use crate::VcpuAArch64;
use crate::VcpuExit;
use crate::VcpuFeature;
use crate::VcpuRegAArch64;
use crate::VcpuSignalHandle;
use crate::VcpuSignalHandleInner;
use crate::Vm;
use crate::VmAArch64;
use crate::VmCap;
use crate::PSCI_0_2;

impl Halla {
    /// Get the size of guest physical addresses (IPA) in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // SAFETY:
        // Safe because we know self is a real halla fd
        match unsafe { ioctl_with_val(self, HVM_CHECK_EXTENSION, HVM_CAP_ARM_VM_IPA_SIZE.into()) } {
            // Default physical address size is 40 bits if the extension is not supported.
            ret if ret <= 0 => 40,
            ipa => ipa as u8,
        }
    }

    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        let ipa_size = self.get_guest_phys_addr_bits() as u32;

        let protection_flag = if protection_type.isolates_memory() {
            HVM_VM_TYPE_ARM_PROTECTED
        } else {
            0
        };
        Ok((ipa_size & HVM_VM_TYPE_IPA_SIZE_MASK) | protection_flag)
    }
}

impl HallaVm {
    /// Does platform specific initialization for the HallaVm.
    pub fn init_arch(&self, cfg: &Config) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        if cfg.mte {
            // SAFETY:
            // Safe because it does not take pointer arguments.
            unsafe { self.ctrl_halla_enable_capability(HallaCap::ArmMte, &[0, 0, 0, 0, 0]) }?;
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
        // TODO: Halla not support pvclock currently
        error!("Halla: not support get_pvclock_arch");
        Err(Error::new(EINVAL))
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.  Always returns an error on AArch64.
    pub fn set_pvclock_arch(&self, _state: &ClockState) -> Result<()> {
        // TODO: Halla not support pvclock currently
        error!("Halla: not support set_pvclock_arch");
        Err(Error::new(EINVAL))
    }

    /// Only return size currently.
    fn get_protected_vm_info(&self) -> Result<u64> {
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel won't write beyond the end of
        // the struct or keep a pointer to it.
        let cap: hvm_enable_cap = unsafe {
            self.ctrl_halla_enable_capability(
                HallaCap::ArmProtectedVm,
                &[HVM_CAP_ARM_PVM_GET_PVMFW_SIZE as u64, 0, 0, 0, 0],
            )
        }?;
        Ok(cap.args[1])
    }

    fn set_protected_vm_firmware_ipa(&self, fw_addr: GuestAddress) -> Result<()> {
        // SAFETY:
        // Safe because none of the args are pointers.
        unsafe {
            self.ctrl_halla_enable_capability(
                HallaCap::ArmProtectedVm,
                &[HVM_CAP_ARM_PVM_SET_PVMFW_IPA as u64, fw_addr.0, 0, 0, 0],
            )
        }?;
        Ok(())
    }
}

impl VmAArch64 for HallaVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.halla
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
        Ok(Box::new(HallaVm::create_vcpu(self, id)?))
    }

    fn create_fdt(&self, _fdt: &mut Fdt, _phandles: &BTreeMap<&str, u32>) -> cros_fdt::Result<()> {
        Ok(())
    }

    fn init_arch(
        &self,
        _payload_entry_address: GuestAddress,
        fdt_address: GuestAddress,
        fdt_size: usize,
    ) -> std::result::Result<(), anyhow::Error> {
        let dtb_config = hvm_dtb_config {
            dtb_addr: fdt_address.offset(),
            dtb_size: fdt_size.try_into().unwrap(),
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will modify exactly the size
        // of the struct.
        let ret = unsafe { ioctl_with_ref(self, HVM_SET_DTB_CONFIG, &dtb_config) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()?
        }
    }
}

impl HallaVcpu {
    fn set_one_halla_reg_u64(&self, hvm_reg_id: HallaVcpuRegister, data: u64) -> Result<()> {
        self.set_one_halla_reg(hvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_halla_reg(&self, hvm_reg_id: HallaVcpuRegister, data: &[u8]) -> Result<()> {
        assert_eq!(hvm_reg_id.size(), data.len());
        let id: u64 = hvm_reg_id.into();
        let onereg = hvm_one_reg {
            id,
            addr: (data.as_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, HVM_SET_ONE_REG, &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_one_halla_reg_u64(&self, hvm_reg_id: HallaVcpuRegister) -> Result<u64> {
        let mut bytes = 0u64.to_ne_bytes();
        self.get_one_halla_reg(hvm_reg_id, bytes.as_mut_slice())?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn get_one_halla_reg(&self, hvm_reg_id: HallaVcpuRegister, data: &mut [u8]) -> Result<()> {
        assert_eq!(hvm_reg_id.size(), data.len());
        let id: u64 = hvm_reg_id.into();
        let onereg = hvm_one_reg {
            id,
            addr: (data.as_mut_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };

        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, HVM_GET_ONE_REG, &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// HVM registers as used by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API
pub enum HallaVcpuRegister {
    /// General Purpose Registers X0-X30
    X(u8),
    /// Stack Pointer
    Sp,
    /// Program Counter
    Pc,
    /// Processor State
    Pstate,
    /// FP & SIMD Registers V0-V31
    V(u8),
    /// Halla Firmware Pseudo-Registers
    Firmware(u16),
    /// System Registers
    System(AArch64SysRegId),
    /// CCSIDR_EL1 Demultiplexed by CSSELR_EL1
    Ccsidr(u8),
}

impl HallaVcpuRegister {
    /// Size of this register in bytes.
    pub fn size(&self) -> usize {
        let hvm_reg = u64::from(*self);
        let size_field = hvm_reg & HVM_REG_SIZE_MASK;
        const REG_SIZE_U8: u64 = HVM_REG_SIZE_U8 as u64; // cast from bindgen's u32 to u64
        match size_field {
            REG_SIZE_U8 => 1,
            HVM_REG_SIZE_U16 => 2,
            HVM_REG_SIZE_U32 => 4,
            HVM_REG_SIZE_U64 => 8,
            HVM_REG_SIZE_U128 => 16,
            HVM_REG_SIZE_U256 => 32,
            HVM_REG_SIZE_U512 => 64,
            HVM_REG_SIZE_U1024 => 128,
            HVM_REG_SIZE_U2048 => 256,
            // `From<HallaVcpuRegister> for u64` should always include a valid size.
            _ => panic!("invalid size field {size_field}"),
        }
    }
}

/// Gives the `u64` register ID expected by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API.
impl From<HallaVcpuRegister> for u64 {
    fn from(register: HallaVcpuRegister) -> Self {
        const fn reg(size: u64, kind: u64, fields: u64) -> u64 {
            HVM_REG_ARM64 | size | kind | fields
        }

        const fn hvm_regs_reg(size: u64, offset: usize) -> u64 {
            let offset = offset / std::mem::size_of::<u32>();

            reg(size, HVM_REG_ARM_CORE as u64, offset as u64)
        }

        const fn hvm_reg(offset: usize) -> u64 {
            hvm_regs_reg(HVM_REG_SIZE_U64, offset)
        }

        fn spsr_reg(spsr_reg: u32) -> u64 {
            let n = std::mem::size_of::<u64>() * (spsr_reg as usize);
            hvm_reg(offset_of!(hvm_regs, spsr) + n)
        }

        fn user_pt_reg(offset: usize) -> u64 {
            hvm_regs_reg(HVM_REG_SIZE_U64, offset_of!(hvm_regs, regs) + offset)
        }

        fn user_fpsimd_state_reg(size: u64, offset: usize) -> u64 {
            hvm_regs_reg(size, offset_of!(hvm_regs, fp_regs) + offset)
        }

        const fn reg_u64(kind: u64, fields: u64) -> u64 {
            reg(HVM_REG_SIZE_U64, kind, fields)
        }

        const fn demux_reg(size: u64, index: u64, value: u64) -> u64 {
            let index = (index << HVM_REG_ARM_DEMUX_ID_SHIFT) & (HVM_REG_ARM_DEMUX_ID_MASK as u64);
            let value =
                (value << HVM_REG_ARM_DEMUX_VAL_SHIFT) & (HVM_REG_ARM_DEMUX_VAL_MASK as u64);

            reg(size, HVM_REG_ARM_DEMUX as u64, index | value)
        }

        match register {
            HallaVcpuRegister::X(n @ 0..=30) => {
                let n = std::mem::size_of::<u64>() * (n as usize);

                user_pt_reg(offset_of!(user_pt_regs, regs) + n)
            }
            HallaVcpuRegister::X(n) => {
                unreachable!("invalid HallaVcpuRegister Xn index: {n}")
            }
            HallaVcpuRegister::Sp => user_pt_reg(offset_of!(user_pt_regs, sp)),
            HallaVcpuRegister::Pc => user_pt_reg(offset_of!(user_pt_regs, pc)),
            HallaVcpuRegister::Pstate => user_pt_reg(offset_of!(user_pt_regs, pstate)),
            HallaVcpuRegister::V(n @ 0..=31) => {
                let n = std::mem::size_of::<u128>() * (n as usize);
                user_fpsimd_state_reg(HVM_REG_SIZE_U128, offset_of!(user_fpsimd_state, vregs) + n)
            }
            HallaVcpuRegister::V(n) => {
                unreachable!("invalid HallaVcpuRegister Vn index: {n}")
            }
            HallaVcpuRegister::System(aarch64_sys_reg::FPSR) => {
                user_fpsimd_state_reg(HVM_REG_SIZE_U32, offset_of!(user_fpsimd_state, fpsr))
            }
            HallaVcpuRegister::System(aarch64_sys_reg::FPCR) => {
                user_fpsimd_state_reg(HVM_REG_SIZE_U32, offset_of!(user_fpsimd_state, fpcr))
            }
            HallaVcpuRegister::System(aarch64_sys_reg::SPSR_EL1) => spsr_reg(0),
            HallaVcpuRegister::System(aarch64_sys_reg::SPSR_abt) => spsr_reg(1),
            HallaVcpuRegister::System(aarch64_sys_reg::SPSR_und) => spsr_reg(2),
            HallaVcpuRegister::System(aarch64_sys_reg::SPSR_irq) => spsr_reg(3),
            HallaVcpuRegister::System(aarch64_sys_reg::SPSR_fiq) => spsr_reg(4),
            HallaVcpuRegister::System(aarch64_sys_reg::SP_EL1) => {
                hvm_reg(offset_of!(hvm_regs, sp_el1))
            }
            HallaVcpuRegister::System(aarch64_sys_reg::ELR_EL1) => {
                hvm_reg(offset_of!(hvm_regs, elr_el1))
            }
            HallaVcpuRegister::System(sysreg) => {
                reg_u64(HVM_REG_ARM64_SYSREG.into(), sysreg.encoded().into())
            }
            HallaVcpuRegister::Firmware(n) => reg_u64(HVM_REG_ARM, n.into()),
            HallaVcpuRegister::Ccsidr(n) => demux_reg(HVM_REG_SIZE_U32, 0, n.into()),
        }
    }
}

impl From<VcpuRegAArch64> for HallaVcpuRegister {
    fn from(reg: VcpuRegAArch64) -> Self {
        match reg {
            VcpuRegAArch64::X(n @ 0..=30) => Self::X(n),
            VcpuRegAArch64::X(n) => unreachable!("invalid VcpuRegAArch64 index: {n}"),
            VcpuRegAArch64::Sp => Self::Sp,
            VcpuRegAArch64::Pc => Self::Pc,
            VcpuRegAArch64::Pstate => Self::Pstate,
            VcpuRegAArch64::System(sysreg) => Self::System(sysreg),
        }
    }
}

impl VcpuAArch64 for HallaVcpu {
    fn init(&self, _features: &[VcpuFeature]) -> Result<()> {
        // Halla init vcpu in creation
        // Return Ok since aarch64/src/lib.rs will use this
        Ok(())
    }

    fn init_pmu(&self, _irq: u64) -> Result<()> {
        // TODO: Halla not support pmu currently
        // temporary return ok since aarch64/src/lib.rs will use this
        Ok(())
    }

    fn has_pvtime_support(&self) -> bool {
        // TODO: Halla not support pvtime currently
        false
    }

    fn init_pvtime(&self, _pvtime_ipa: u64) -> Result<()> {
        // TODO: Halla not support pvtime currently
        error!("Halla: not support init_pvtime");
        Err(Error::new(EINVAL))
    }

    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()> {
        self.set_one_halla_reg_u64(HallaVcpuRegister::from(reg_id), data)
    }

    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64> {
        self.get_one_halla_reg_u64(HallaVcpuRegister::from(reg_id))
    }

    fn set_vector_reg(&self, _reg_num: u8, _data: u128) -> Result<()> {
        unimplemented!()
    }

    fn get_vector_reg(&self, _reg_num: u8) -> Result<u128> {
        unimplemented!()
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        Ok(PSCI_0_2)
    }

    fn get_max_hw_bps(&self) -> Result<usize> {
        // TODO: Halla not support gdb currently
        error!("Halla: not support get_max_hw_bps");
        Err(Error::new(EINVAL))
    }

    fn get_system_regs(&self) -> Result<BTreeMap<AArch64SysRegId, u64>> {
        error!("Halla: not support get_system_regs");
        Err(Error::new(EINVAL))
    }

    fn get_cache_info(&self) -> Result<BTreeMap<u8, u64>> {
        error!("Halla: not support get_cache_info");
        Err(Error::new(EINVAL))
    }

    fn set_cache_info(&self, _cache_info: BTreeMap<u8, u64>) -> Result<()> {
        error!("Halla: not support set_cache_info");
        Err(Error::new(EINVAL))
    }

    fn hypervisor_specific_snapshot(&self) -> anyhow::Result<AnySnapshot> {
        // TODO: Halla not support gdb currently
        Err(anyhow::anyhow!(
            "Halla: not support hypervisor_specific_snapshot"
        ))
    }

    fn hypervisor_specific_restore(&self, _data: AnySnapshot) -> anyhow::Result<()> {
        // TODO: Halla not support gdb currently
        Err(anyhow::anyhow!(
            "Halla: not support hypervisor_specific_restore"
        ))
    }

    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        // TODO: Halla not support gdb currently
        error!("Halla: not support set_guest_debug");
        Err(Error::new(EINVAL))
    }
}

// Wrapper around HVM_SET_USER_MEMORY_REGION ioctl, which creates, modifies, or deletes a mapping
// from guest physical to host user pages.
//
// SAFETY:
// Safe when the guest regions are guaranteed not to overlap.
unsafe fn set_user_memory_region(
    descriptor: &SafeDescriptor,
    slot: MemSlot,
    guest_addr: u64,
    memory_size: u64,
    userspace_addr: *mut u8,
    flags: u32,
) -> Result<()> {
    let region = hvm_userspace_memory_region {
        slot,
        flags,
        guest_phys_addr: guest_addr,
        memory_size,
        userspace_addr: userspace_addr as u64,
    };

    let ret = ioctl_with_ref(descriptor, HVM_SET_USER_MEMORY_REGION, &region);
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
    size.div_ceil(page_size).div_ceil(8)
}

pub struct Halla {
    halla: SafeDescriptor,
}

#[repr(u32)]
pub enum HallaCap {
    ArmMte,
    ArmProtectedVm = HVM_CAP_ARM_PROTECTED_VM,
}

impl Halla {
    pub fn new_with_path(device_path: &Path) -> Result<Halla> {
        let c_path = CString::new(device_path.as_os_str().as_bytes()).unwrap();
        // SAFETY:
        // Open calls are safe because we give a nul-terminated string and verify the result.
        let ret = unsafe { open(c_path.as_ptr(), O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        Ok(Halla {
            // SAFETY:
            // Safe because we verify that ret is valid and we own the fd.
            halla: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
        })
    }

    /// Opens `/dev/halla/` and returns a hvm object on success.
    pub fn new() -> Result<Halla> {
        Halla::new_with_path(&PathBuf::from("/dev/halla"))
    }

    /// Gets the size of the mmap required to use vcpu's `hvm_vcpu_run` structure.
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // We don't use mmap, return sizeof(hvm_vcpu_run) directly
        let res = std::mem::size_of::<hvm_vcpu_run>();
        Ok(res)
    }
}

impl AsRawDescriptor for Halla {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.halla.as_raw_descriptor()
    }
}

impl Hypervisor for Halla {
    fn try_clone(&self) -> Result<Self> {
        Ok(Halla {
            halla: self.halla.try_clone()?,
        })
    }

    fn check_capability(&self, cap: HypervisorCap) -> bool {
        match cap {
            HypervisorCap::UserMemory => true,
            HypervisorCap::ImmediateExit => true,
            HypervisorCap::StaticSwiotlbAllocationRequired => false,
            HypervisorCap::HypervisorInitializedBootContext => false,
        }
    }
}

/// A wrapper around creating and using a Halla VM.
pub struct HallaVm {
    halla: Halla,
    vm: SafeDescriptor,
    guest_mem: GuestMemory,
    mem_regions: Arc<Mutex<BTreeMap<MemSlot, Box<dyn MappedRegion>>>>,
    /// A min heap of MemSlot numbers that were used and then removed and can now be re-used
    mem_slot_gaps: Arc<Mutex<BinaryHeap<Reverse<MemSlot>>>>,
}

impl HallaVm {
    /// Constructs a new `HallaVm` using the given `Halla` instance.
    pub fn new(halla: &Halla, guest_mem: GuestMemory, cfg: Config) -> Result<HallaVm> {
        // SAFETY:
        // Safe because we know hvm is a real hvm fd as this module is the only one that can make
        // hvm objects.
        let ret = unsafe {
            ioctl_with_val(
                halla,
                HVM_CREATE_VM,
                halla.get_vm_type(cfg.protection_type)? as c_ulong,
            )
        };
        if ret < 0 {
            return errno_result();
        }
        // SAFETY:
        // Safe because we verify that ret is valid and we own the fd.
        let vm_descriptor = unsafe { SafeDescriptor::from_raw_descriptor(ret) };
        for region in guest_mem.regions() {
            let flags = match region.options.purpose {
                MemoryRegionPurpose::Bios => HVM_USER_MEM_REGION_GUEST_MEM,
                MemoryRegionPurpose::GuestMemoryRegion => HVM_USER_MEM_REGION_GUEST_MEM,
                MemoryRegionPurpose::ProtectedFirmwareRegion => HVM_USER_MEM_REGION_PROTECT_FW,
                MemoryRegionPurpose::ReservedMemory => HVM_USER_MEM_REGION_GUEST_MEM,
                MemoryRegionPurpose::StaticSwiotlbRegion => HVM_USER_MEM_REGION_STATIC_SWIOTLB,
            };
            // SAFETY:
            // Safe because the guest regions are guaranteed not to overlap.
            unsafe {
                set_user_memory_region(
                    &vm_descriptor,
                    region.index as MemSlot,
                    region.guest_addr.offset(),
                    region.size as u64,
                    region.host_addr as *mut u8,
                    flags,
                )
            }?;
        }

        let vm = HallaVm {
            halla: halla.try_clone()?,
            vm: vm_descriptor,
            guest_mem,
            mem_regions: Arc::new(Mutex::new(BTreeMap::new())),
            mem_slot_gaps: Arc::new(Mutex::new(BinaryHeap::new())),
        };
        vm.init_arch(&cfg)?;
        Ok(vm)
    }

    fn create_vcpu(&self, id: usize) -> Result<HallaVcpu> {
        // run is a data structure shared with ko and halla
        let run_mmap_size = self.halla.get_vcpu_mmap_size()?;

        let fd =
            // SAFETY:
            // Safe because we know that our file is a VM fd and we verify the return result.
            unsafe { ioctl_with_val(self, HVM_CREATE_VCPU, c_ulong::try_from(id).unwrap()) };

        if fd < 0 {
            return errno_result();
        }

        // SAFETY:
        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { SafeDescriptor::from_raw_descriptor(fd) };

        // Memory mapping --> Memory allocation
        let run_mmap = MemoryMappingBuilder::new(run_mmap_size)
            .build()
            .map_err(|_| Error::new(ENOSPC))?;

        Ok(HallaVcpu {
            vm: self.vm.try_clone()?,
            vcpu,
            id,
            run_mmap: Arc::new(run_mmap),
        })
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        let mut irq_level = hvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = active as u32;

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, HVM_IRQ_LINE, &irq_level) };
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
        let mut irqfd = hvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            ..Default::default()
        };

        if let Some(r_evt) = resample_evt {
            irqfd.flags = HVM_IRQFD_FLAG_RESAMPLE;
            irqfd.resamplefd = r_evt.as_raw_descriptor() as u32;
        }

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, HVM_IRQFD, &irqfd) };
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
        let irqfd = hvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            flags: HVM_IRQFD_FLAG_DEASSIGN,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, HVM_IRQFD, &irqfd) };
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
                Some(u) => (true, u, 8),
                None => (false, 0, 8),
            },
        };
        let mut flags = 0;
        if deassign {
            flags |= 1 << hvm_ioeventfd_flag_nr_deassign;
        }
        if do_datamatch {
            flags |= 1 << hvm_ioeventfd_flag_nr_datamatch
        }
        let ioeventfd = hvm_ioeventfd {
            datamatch: datamatch_value,
            len: datamatch_len,
            addr: match addr {
                IoEventAddress::Mmio(m) => m,
                // We don't use Pio in aarch64, If we need to support x86, please add it.
                IoEventAddress::Pio(_) => EINVAL.try_into().unwrap(),
            },
            fd: evt.as_raw_descriptor(),
            flags,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, HVM_IOEVENTFD, &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Checks whether a particular HVM-specific capability is available for this VM.
    fn check_raw_capability(&self, capability: HallaCap) -> bool {
        let mut cap: u64 = capability as u64;
        // SAFETY:
        // Safe because we know that our file is a HVM fd, and if the cap is invalid HVM assumes
        // it's an unavailable extension and returns 0.
        unsafe {
            ioctl_with_mut_ref(self, HVM_CHECK_EXTENSION, &mut cap);
        }
        cap == 1
    }

    #[allow(dead_code)]
    /// Enables a HVM-specific capability for this VM, with the given arguments.
    ///
    /// # Safety
    /// This function is marked as unsafe because `args` may be interpreted as pointers for some
    /// capabilities. The caller must ensure that any pointers passed in the `args` array are
    /// allocated as the kernel expects, and that mutable pointers are owned.
    unsafe fn ctrl_halla_enable_capability(
        &self,
        capability: HallaCap,
        args: &[u64; 5],
    ) -> Result<hvm_enable_cap> {
        let hvm_cap = hvm_enable_cap {
            cap: capability as u64,
            args: *args,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct, and because we assume the caller has allocated the args appropriately.
        let ret = ioctl_with_ref(self, HVM_ENABLE_CAP, &hvm_cap);
        if ret == 0 {
            Ok(hvm_cap)
        } else {
            errno_result()
        }
    }

    pub fn create_halla_device(&self, dev: hvm_create_device) -> Result<()> {
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will modify exactly the size
        // of the struct and the return value is checked.
        let ret = unsafe { base::ioctl_with_ref(self, HVM_CREATE_DEVICE, &dev) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
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
        // No-op, when the guest attempts to access the pages again, Linux/HVM will provide them.
        Ok(())
    }
}

impl Vm for HallaVm {
    fn try_clone(&self) -> Result<Self> {
        Ok(HallaVm {
            halla: self.halla.try_clone()?,
            vm: self.vm.try_clone()?,
            guest_mem: self.guest_mem.clone(),
            mem_regions: self.mem_regions.clone(),
            mem_slot_gaps: self.mem_slot_gaps.clone(),
        })
    }

    fn try_clone_descriptor(&self) -> Result<SafeDescriptor> {
        error!("try_clone_descriptor hasn't been tested on Halla, returning -ENOTSUP");
        Err(Error::new(ENOTSUP))
    }

    fn hypervisor_kind(&self) -> HypervisorKind {
        HypervisorKind::Halla
    }

    fn check_capability(&self, c: VmCap) -> bool {
        if let Some(val) = self.check_capability_arch(c) {
            return val;
        }
        match c {
            VmCap::ArmPmuV3 => false,
            VmCap::DirtyLog => false,
            VmCap::PvClock => false,
            VmCap::Protected => self.check_raw_capability(HallaCap::ArmProtectedVm),
            VmCap::EarlyInitCpuid => false,
            VmCap::ReadOnlyMemoryRegion => false,
            VmCap::MemNoncoherentDma => false,
            VmCap::Sve => false,
        }
    }

    fn get_guest_phys_addr_bits(&self) -> u8 {
        self.halla.get_guest_phys_addr_bits()
    }

    fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    fn add_memory_region(
        &mut self,
        guest_addr: GuestAddress,
        mem: Box<dyn MappedRegion>,
        _read_only: bool,
        _log_dirty_pages: bool,
        _cache: MemCacheType,
    ) -> Result<MemSlot> {
        let pgsz = pagesize() as u64;
        // HVM require to set the user memory region with page size aligned size. Safe to extend
        // the mem.size() to be page size aligned because the mmap will round up the size to be
        // page size aligned if it is not.
        let size = (mem.size() as u64).div_ceil(pgsz) * pgsz;
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
        let flags = 0;

        // SAFETY:
        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        // We don't use read_only and log_dirty_pages, if we need this, please add it
        let res = unsafe {
            set_user_memory_region(
                &self.vm,
                slot,
                guest_addr.offset(),
                size,
                mem.as_ptr(),
                flags,
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

    fn madvise_pageout_memory_region(
        &mut self,
        _slot: MemSlot,
        _offset: usize,
        _size: usize,
    ) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    fn madvise_remove_memory_region(
        &mut self,
        _slot: MemSlot,
        _offset: usize,
        _size: usize,
    ) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    fn remove_memory_region(&mut self, slot: MemSlot) -> Result<Box<dyn MappedRegion>> {
        let mut regions = self.mem_regions.lock();
        if !regions.contains_key(&slot) {
            return Err(Error::new(ENOENT));
        }
        // SAFETY:
        // Safe because the slot is checked against the list of memory slots.
        unsafe {
            set_user_memory_region(&self.vm, slot, 0, 0, std::ptr::null_mut(), 0)?;
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
        // HVM delivers IO events in-kernel with ioeventfds, so this is a no-op
        Ok(())
    }

    fn enable_hypercalls(&mut self, _nr: u64, _count: usize) -> Result<()> {
        Err(Error::new(ENOTSUP))
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

    fn handle_balloon_event(&mut self, event: BalloonEvent) -> Result<()> {
        match event {
            BalloonEvent::Inflate(m) => self.handle_inflate(m.guest_address, m.size),
            BalloonEvent::Deflate(m) => self.handle_deflate(m.guest_address, m.size),
            BalloonEvent::BalloonTargetReached(_) => Ok(()),
        }
    }
}

impl AsRawDescriptor for HallaVm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vm.as_raw_descriptor()
    }
}

struct HallaVcpuSignalHandle {
    run_mmap: Arc<MemoryMapping>,
}

impl VcpuSignalHandleInner for HallaVcpuSignalHandle {
    fn signal_immediate_exit(&self) {
        // SAFETY: we ensure `run_mmap` is a valid mapping of `halla_run` at creation time, and the
        // `Arc` ensures the mapping still exists while we hold a reference to it.
        unsafe {
            let run = self.run_mmap.as_ptr() as *mut hvm_vcpu_run;
            (*run).immediate_exit = 1;
        }
    }
}

/// A wrapper around using a Halla Vcpu.
pub struct HallaVcpu {
    vm: SafeDescriptor,
    vcpu: SafeDescriptor,
    id: usize,
    run_mmap: Arc<MemoryMapping>,
}

impl Vcpu for HallaVcpu {
    fn try_clone(&self) -> Result<Self> {
        let vm = self.vm.try_clone()?;
        let vcpu = self.vcpu.try_clone()?;

        Ok(HallaVcpu {
            vm,
            vcpu,
            id: self.id,
            run_mmap: self.run_mmap.clone(),
        })
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    fn id(&self) -> usize {
        self.id
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn set_immediate_exit(&self, exit: bool) {
        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut hvm_vcpu_run) };
        run.immediate_exit = exit as u8;
    }

    fn signal_handle(&self) -> VcpuSignalHandle {
        VcpuSignalHandle {
            inner: Box::new(HallaVcpuSignalHandle {
                run_mmap: self.run_mmap.clone(),
            }),
        }
    }

    fn on_suspend(&self) -> Result<()> {
        Ok(())
    }

    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        Err(Error::new(libc::ENXIO))
    }

    #[allow(clippy::cast_ptr_alignment)]
    // The pointer is page aligned so casting to a different type is well defined, hence the clippy
    // allow attribute.
    fn run(&mut self) -> Result<VcpuExit> {
        // SAFETY:
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, HVM_RUN, self.run_mmap.as_ptr() as u64) };
        if ret != 0 {
            return errno_result();
        }

        // SAFETY:
        // Safe because we know we mapped enough memory to hold the hvm_vcpu_run struct because the
        // kernel told us how large it was.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut hvm_vcpu_run) };

        match run.exit_reason {
            HVM_EXIT_MMIO => Ok(VcpuExit::Mmio),
            HVM_EXIT_IRQ => Ok(VcpuExit::IrqWindowOpen),
            HVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
            HVM_EXIT_SYSTEM_EVENT => {
                // SAFETY:
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let event_type = unsafe { run.__bindgen_anon_1.system_event.type_ };
                match event_type {
                    HVM_SYSTEM_EVENT_SHUTDOWN => Ok(VcpuExit::SystemEventShutdown),
                    HVM_SYSTEM_EVENT_RESET => Ok(VcpuExit::SystemEventReset),
                    HVM_SYSTEM_EVENT_CRASH => Ok(VcpuExit::SystemEventCrash),
                    _ => {
                        error!("Unknown HVM system event {}", event_type);
                        Err(Error::new(EINVAL))
                    }
                }
            }
            HVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
            HVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown(Ok(()))),
            r => panic!("unknown hvm exit reason: {r}"),
        }
    }

    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the hvm_vcpu_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut hvm_vcpu_run) };

        // Verify that the handler is called in the right context.
        assert!(run.exit_reason == HVM_EXIT_MMIO);
        // SAFETY:
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.
        let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
        let address = mmio.phys_addr;
        let data = &mut mmio.data[..mmio.size as usize];

        if mmio.is_write != 0 {
            handle_fn(IoParams {
                address,
                operation: IoOperation::Write(data),
            })
        } else {
            handle_fn(IoParams {
                address,
                operation: IoOperation::Read(data),
            })
        }
    }

    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
        Err(Error::new(EINVAL))
    }
}

impl AsRawDescriptor for HallaVcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vcpu.as_raw_descriptor()
    }
}
