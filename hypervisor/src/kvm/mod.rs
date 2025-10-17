// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aarch64;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use aarch64::*;

mod cap;
pub use cap::KvmCap;

#[cfg(target_arch = "riscv64")]
mod riscv64;

#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::convert::TryFrom;
use std::ffi::CString;
use std::fs::File;
use std::os::raw::c_ulong;
use std::os::raw::c_void;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

use base::errno_result;
use base::error;
use base::ioctl;
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
use data_model::vec_with_array_field;
use kvm_sys::*;
use libc::open64;
use libc::EFAULT;
use libc::EINVAL;
use libc::EIO;
use libc::ENOENT;
use libc::ENOSPC;
use libc::ENOSYS;
use libc::EOVERFLOW;
use libc::O_CLOEXEC;
use libc::O_RDWR;
#[cfg(target_arch = "riscv64")]
use riscv64::*;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

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
use crate::IrqRoute;
use crate::IrqSource;
use crate::MPState;
use crate::MemCacheType;
use crate::MemSlot;
use crate::Vcpu;
use crate::VcpuExit;
use crate::VcpuSignalHandle;
use crate::VcpuSignalHandleInner;
use crate::Vm;
use crate::VmCap;

// Wrapper around KVM_SET_USER_MEMORY_REGION ioctl, which creates, modifies, or deletes a mapping
// from guest physical to host user pages.
//
// SAFETY:
// Safe when the guest regions are guaranteed not to overlap.
unsafe fn set_user_memory_region(
    kvm: &KvmVm,
    slot: MemSlot,
    read_only: bool,
    log_dirty_pages: bool,
    cache: MemCacheType,
    guest_addr: u64,
    memory_size: u64,
    userspace_addr: *mut u8,
) -> Result<()> {
    let mut use_2_variant = false;
    let mut flags = 0;
    if read_only {
        flags |= KVM_MEM_READONLY;
    }
    if log_dirty_pages {
        flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }
    if kvm.caps.user_noncoherent_dma && cache == MemCacheType::CacheNonCoherent {
        flags |= KVM_MEM_NON_COHERENT_DMA;
        use_2_variant = kvm.caps.user_memory_region2;
    }

    let untagged_userspace_addr = untagged_addr(userspace_addr as usize);
    let ret = if use_2_variant {
        let region2 = kvm_userspace_memory_region2 {
            slot,
            flags,
            guest_phys_addr: guest_addr,
            memory_size,
            userspace_addr: untagged_userspace_addr as u64,
            guest_memfd_offset: 0,
            guest_memfd: 0,
            ..Default::default()
        };
        ioctl_with_ref(&kvm.vm, KVM_SET_USER_MEMORY_REGION2, &region2)
    } else {
        let region = kvm_userspace_memory_region {
            slot,
            flags,
            guest_phys_addr: guest_addr,
            memory_size,
            userspace_addr: (untagged_userspace_addr as u64),
        };
        ioctl_with_ref(&kvm.vm, KVM_SET_USER_MEMORY_REGION, &region)
    };

    if ret == 0 {
        Ok(())
    } else {
        errno_result()
    }
}

// https://github.com/torvalds/linux/blob/master/Documentation/virt/kvm/api.rst
// On architectures that support a form of address tagging, userspace_addr must be an untagged
// address.
#[inline]
fn untagged_addr(addr: usize) -> usize {
    let tag_bits_mask: u64 = if cfg!(target_arch = "aarch64") {
        0xFF00000000000000
    } else {
        0
    };
    addr & !tag_bits_mask as usize
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

pub struct Kvm {
    kvm: SafeDescriptor,
    vcpu_mmap_size: usize,
}

impl Kvm {
    pub fn new_with_path(device_path: &Path) -> Result<Kvm> {
        let c_path = CString::new(device_path.as_os_str().as_bytes()).unwrap();
        // SAFETY:
        // Open calls are safe because we give a nul-terminated string and verify the result.
        let ret = unsafe { open64(c_path.as_ptr(), O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        // SAFETY:
        // Safe because we verify that ret is valid and we own the fd.
        let kvm = unsafe { SafeDescriptor::from_raw_descriptor(ret) };

        // SAFETY:
        // Safe because we know that the descriptor is valid and we verify the return result.
        let version = unsafe { ioctl(&kvm, KVM_GET_API_VERSION) };
        if version < 0 {
            return errno_result();
        }

        // Per the kernel KVM API documentation: "Applications should refuse to run if
        // KVM_GET_API_VERSION returns a value other than 12."
        if version as u32 != KVM_API_VERSION {
            error!(
                "KVM_GET_API_VERSION: expected {}, got {}",
                KVM_API_VERSION, version,
            );
            return Err(Error::new(ENOSYS));
        }

        // SAFETY:
        // Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(&kvm, KVM_GET_VCPU_MMAP_SIZE) };
        if res <= 0 {
            return errno_result();
        }
        let vcpu_mmap_size = res as usize;

        Ok(Kvm {
            kvm,
            vcpu_mmap_size,
        })
    }

    /// Opens `/dev/kvm` and returns a Kvm object on success.
    pub fn new() -> Result<Kvm> {
        Kvm::new_with_path(Path::new("/dev/kvm"))
    }
}

impl AsRawDescriptor for Kvm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.kvm.as_raw_descriptor()
    }
}

impl Hypervisor for Kvm {
    fn try_clone(&self) -> Result<Self> {
        Ok(Kvm {
            kvm: self.kvm.try_clone()?,
            vcpu_mmap_size: self.vcpu_mmap_size,
        })
    }

    fn check_capability(&self, cap: HypervisorCap) -> bool {
        if let Ok(kvm_cap) = KvmCap::try_from(cap) {
            // SAFETY:
            // this ioctl is safe because we know this kvm descriptor is valid,
            // and we are copying over the kvm capability (u32) as a c_ulong value.
            unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION, kvm_cap as c_ulong) == 1 }
        } else {
            // this capability cannot be converted on this platform, so return false
            false
        }
    }
}

/// Storage for constant KVM driver caps
#[derive(Clone, Default)]
struct KvmVmCaps {
    kvmclock_ctrl: bool,
    user_noncoherent_dma: bool,
    user_memory_region2: bool,
    // This capability can't be detected until after the irqchip is configured, so we lazy
    // initialize it when the first MSI is configured.
    msi_devid: Arc<OnceLock<bool>>,
}

/// A wrapper around creating and using a KVM VM.
pub struct KvmVm {
    kvm: Kvm,
    vm: SafeDescriptor,
    guest_mem: GuestMemory,
    mem_regions: Arc<Mutex<BTreeMap<MemSlot, Box<dyn MappedRegion>>>>,
    /// A min heap of MemSlot numbers that were used and then removed and can now be re-used
    mem_slot_gaps: Arc<Mutex<BinaryHeap<Reverse<MemSlot>>>>,
    caps: KvmVmCaps,
    force_disable_readonly_mem: bool,
}

impl KvmVm {
    /// Constructs a new `KvmVm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm, guest_mem: GuestMemory, cfg: Config) -> Result<KvmVm> {
        // SAFETY:
        // Safe because we know kvm is a real kvm fd as this module is the only one that can make
        // Kvm objects.
        let ret = unsafe {
            ioctl_with_val(
                kvm,
                KVM_CREATE_VM,
                kvm.get_vm_type(cfg.protection_type)? as c_ulong,
            )
        };
        if ret < 0 {
            return errno_result();
        }
        // SAFETY:
        // Safe because we verify that ret is valid and we own the fd.
        let vm_descriptor = unsafe { SafeDescriptor::from_raw_descriptor(ret) };
        let mut vm = KvmVm {
            kvm: kvm.try_clone()?,
            vm: vm_descriptor,
            guest_mem,
            mem_regions: Arc::new(Mutex::new(BTreeMap::new())),
            mem_slot_gaps: Arc::new(Mutex::new(BinaryHeap::new())),
            caps: Default::default(),
            force_disable_readonly_mem: cfg.force_disable_readonly_mem,
        };
        vm.caps.kvmclock_ctrl = vm.check_raw_capability(KvmCap::KvmclockCtrl);
        vm.caps.user_noncoherent_dma = vm.check_raw_capability(KvmCap::MemNoncoherentDma);
        vm.caps.user_memory_region2 = vm.check_raw_capability(KvmCap::UserMemory2);

        vm.init_arch(&cfg)?;

        for region in vm.guest_mem.regions() {
            // SAFETY:
            // Safe because the guest regions are guaranteed not to overlap.
            unsafe {
                set_user_memory_region(
                    &vm,
                    region.index as MemSlot,
                    false,
                    false,
                    MemCacheType::CacheCoherent,
                    region.guest_addr.offset(),
                    region.size as u64,
                    region.host_addr as *mut u8,
                )
            }?;
        }

        Ok(vm)
    }

    pub fn create_kvm_vcpu(&self, id: usize) -> Result<KvmVcpu> {
        // SAFETY:
        // Safe because we know that our file is a VM fd and we verify the return result.
        let fd = unsafe { ioctl_with_val(self, KVM_CREATE_VCPU, c_ulong::try_from(id).unwrap()) };
        if fd < 0 {
            return errno_result();
        }

        // SAFETY:
        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_descriptor(fd) };

        // The VCPU mapping is held by an `Arc` inside `KvmVcpu`, and it can also be cloned by
        // `signal_handle()` for use in `KvmVcpuSignalHandle`. The mapping will not be destroyed
        // until all references are dropped, so it is safe to reference `kvm_run` fields via the
        // `as_ptr()` function during either type's lifetime.
        let run_mmap = MemoryMappingBuilder::new(self.kvm.vcpu_mmap_size)
            .from_file(&vcpu)
            .build()
            .map_err(|_| Error::new(ENOSPC))?;

        Ok(KvmVcpu {
            kvm: self.kvm.try_clone()?,
            vm: self.vm.try_clone()?,
            vcpu,
            id,
            cap_kvmclock_ctrl: self.caps.kvmclock_ctrl,
            run_mmap: Arc::new(run_mmap),
        })
    }

    /// Creates an in kernel interrupt controller.
    ///
    /// See the documentation on the KVM_CREATE_IRQCHIP ioctl.
    pub fn create_irq_chip(&self) -> Result<()> {
        // SAFETY:
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        let mut irq_level = kvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = active.into();

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQ_LINE, &irq_level) };
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
        let mut irqfd = kvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            ..Default::default()
        };

        if let Some(r_evt) = resample_evt {
            irqfd.flags = KVM_IRQFD_FLAG_RESAMPLE;
            irqfd.resamplefd = r_evt.as_raw_descriptor() as u32;
        }

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD, &irqfd) };
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
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            flags: KVM_IRQFD_FLAG_DEASSIGN,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD, &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the GSI routing table, replacing any table set with previous calls to
    /// `set_gsi_routing`.
    pub fn set_gsi_routing(&self, routes: &[IrqRoute]) -> Result<()> {
        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(routes.len());
        irq_routing[0].nr = routes.len() as u32;

        let cap_msi_devid = *self
            .caps
            .msi_devid
            .get_or_init(|| self.check_raw_capability(KvmCap::MsiDevid));

        // SAFETY:
        // Safe because we ensured there is enough space in irq_routing to hold the number of
        // route entries.
        let irq_routes = unsafe { irq_routing[0].entries.as_mut_slice(routes.len()) };
        for (route, irq_route) in routes.iter().zip(irq_routes.iter_mut()) {
            *irq_route = to_kvm_irq_routing_entry(route, cap_msi_devid);
        }

        // TODO(b/315998194): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GSI_ROUTING, &irq_routing[0]) };
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
            flags |= 1 << kvm_ioeventfd_flag_nr_deassign;
        }
        if do_datamatch {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        if let IoEventAddress::Pio(_) = addr {
            flags |= 1 << kvm_ioeventfd_flag_nr_pio;
        }
        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch_value,
            len: datamatch_len,
            addr: match addr {
                IoEventAddress::Pio(p) => p,
                IoEventAddress::Mmio(m) => m,
            },
            fd: evt.as_raw_descriptor(),
            flags,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IOEVENTFD, &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Checks whether a particular KVM-specific capability is available for this VM.
    pub fn check_raw_capability(&self, capability: KvmCap) -> bool {
        // SAFETY:
        // Safe because we know that our file is a KVM fd, and if the cap is invalid KVM assumes
        // it's an unavailable extension and returns 0.
        let ret = unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION, capability as c_ulong) };
        match capability {
            #[cfg(target_arch = "x86_64")]
            KvmCap::BusLockDetect => {
                if ret > 0 {
                    ret as u32 & KVM_BUS_LOCK_DETECTION_EXIT == KVM_BUS_LOCK_DETECTION_EXIT
                } else {
                    false
                }
            }
            _ => ret == 1,
        }
    }

    // Currently only used on aarch64, but works on any architecture.
    #[allow(dead_code)]
    /// Enables a KVM-specific capability for this VM, with the given arguments.
    ///
    /// # Safety
    /// This function is marked as unsafe because `args` may be interpreted as pointers for some
    /// capabilities. The caller must ensure that any pointers passed in the `args` array are
    /// allocated as the kernel expects, and that mutable pointers are owned.
    unsafe fn enable_raw_capability(
        &self,
        capability: KvmCap,
        flags: u32,
        args: &[u64; 4],
    ) -> Result<()> {
        let kvm_cap = kvm_enable_cap {
            cap: capability as u32,
            args: *args,
            flags,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct, and because we assume the caller has allocated the args appropriately.
        let ret = ioctl_with_ref(self, KVM_ENABLE_CAP, &kvm_cap);
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn handle_inflate(&mut self, guest_address: GuestAddress, size: u64) -> Result<()> {
        match if self.guest_mem.use_punchhole_locked() {
            self.guest_mem.punch_hole_range(guest_address, size)
        } else {
            self.guest_mem.remove_range(guest_address, size)
        } {
            Ok(_) => Ok(()),
            Err(vm_memory::Error::MemoryAccess(_, MmapError::SystemCallFailed(e))) => Err(e),
            Err(_) => Err(Error::new(EIO)),
        }
    }

    fn handle_deflate(&mut self, _guest_address: GuestAddress, _size: u64) -> Result<()> {
        // No-op, when the guest attempts to access the pages again, Linux/KVM will provide them.
        Ok(())
    }
}

impl Vm for KvmVm {
    fn try_clone(&self) -> Result<Self> {
        Ok(KvmVm {
            kvm: self.kvm.try_clone()?,
            vm: self.vm.try_clone()?,
            guest_mem: self.guest_mem.clone(),
            mem_regions: self.mem_regions.clone(),
            mem_slot_gaps: self.mem_slot_gaps.clone(),
            caps: self.caps.clone(),
            force_disable_readonly_mem: self.force_disable_readonly_mem,
        })
    }

    fn try_clone_descriptor(&self) -> Result<SafeDescriptor> {
        self.vm.try_clone()
    }

    fn hypervisor_kind(&self) -> HypervisorKind {
        HypervisorKind::Kvm
    }

    fn check_capability(&self, c: VmCap) -> bool {
        if let Some(val) = self.check_capability_arch(c) {
            return val;
        }
        match c {
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            VmCap::ArmPmuV3 => self.check_raw_capability(KvmCap::ArmPmuV3),
            VmCap::DirtyLog => true,
            VmCap::PvClock => false,
            VmCap::Protected => self.check_raw_capability(KvmCap::ArmProtectedVm),
            VmCap::EarlyInitCpuid => false,
            #[cfg(target_arch = "x86_64")]
            VmCap::BusLockDetect => self.check_raw_capability(KvmCap::BusLockDetect),
            VmCap::ReadOnlyMemoryRegion => {
                !self.force_disable_readonly_mem && self.check_raw_capability(KvmCap::ReadonlyMem)
            }
            VmCap::MemNoncoherentDma => {
                cfg!(feature = "noncoherent-dma")
                    && self.check_raw_capability(KvmCap::MemNoncoherentDma)
            }
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            VmCap::Sve => self.check_raw_capability(KvmCap::Sve),
        }
    }

    fn enable_capability(&self, c: VmCap, _flags: u32) -> Result<bool> {
        match c {
            #[cfg(target_arch = "x86_64")]
            VmCap::BusLockDetect => {
                let args = [KVM_BUS_LOCK_DETECTION_EXIT as u64, 0, 0, 0];
                Ok(
                    // TODO(b/315998194): Add safety comment
                    #[allow(clippy::undocumented_unsafe_blocks)]
                    unsafe {
                        self.enable_raw_capability(KvmCap::BusLockDetect, _flags, &args) == Ok(())
                    },
                )
            }
            _ => Ok(false),
        }
    }

    fn get_guest_phys_addr_bits(&self) -> u8 {
        self.kvm.get_guest_phys_addr_bits()
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
        cache: MemCacheType,
    ) -> Result<MemSlot> {
        let pgsz = pagesize() as u64;
        // KVM require to set the user memory region with page size aligned size. Safe to extend
        // the mem.size() to be page size aligned because the mmap will round up the size to be
        // page size aligned if it is not.
        let size = (mem.size() as u64).next_multiple_of(pgsz);
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

        // SAFETY:
        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        let res = unsafe {
            set_user_memory_region(
                self,
                slot,
                read_only,
                log_dirty_pages,
                cache,
                guest_addr.offset(),
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

    fn madvise_pageout_memory_region(
        &mut self,
        slot: MemSlot,
        offset: usize,
        size: usize,
    ) -> Result<()> {
        let mut regions = self.mem_regions.lock();
        let mem = regions.get_mut(&slot).ok_or_else(|| Error::new(ENOENT))?;

        mem.madvise(offset, size, libc::MADV_PAGEOUT)
            .map_err(|err| match err {
                MmapError::InvalidAddress => Error::new(EFAULT),
                MmapError::NotPageAligned => Error::new(EINVAL),
                MmapError::SystemCallFailed(e) => e,
                _ => Error::new(EIO),
            })
    }

    fn madvise_remove_memory_region(
        &mut self,
        slot: MemSlot,
        offset: usize,
        size: usize,
    ) -> Result<()> {
        let mut regions = self.mem_regions.lock();
        let mem = regions.get_mut(&slot).ok_or_else(|| Error::new(ENOENT))?;

        mem.madvise(offset, size, libc::MADV_REMOVE)
            .map_err(|err| match err {
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
        // SAFETY:
        // Safe because the slot is checked against the list of memory slots.
        unsafe {
            set_user_memory_region(
                self,
                slot,
                false,
                false,
                MemCacheType::CacheCoherent,
                0,
                0,
                std::ptr::null_mut(),
            )?;
        }
        self.mem_slot_gaps.lock().push(Reverse(slot));
        // This remove will always succeed because of the contains_key check above.
        Ok(regions.remove(&slot).unwrap())
    }

    fn create_device(&self, kind: DeviceKind) -> Result<SafeDescriptor> {
        let mut device = if let Some(dev) = self.get_device_params_arch(kind) {
            dev
        } else {
            match kind {
                DeviceKind::Vfio => kvm_create_device {
                    type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
                    fd: 0,
                    flags: 0,
                },

                // ARM and risc-v have additional DeviceKinds, so it needs the catch-all pattern
                #[cfg(any(target_arch = "arm", target_arch = "aarch64", target_arch = "riscv64"))]
                _ => return Err(Error::new(libc::ENXIO)),
            }
        };

        // SAFETY:
        // Safe because we know that our file is a VM fd, we know the kernel will only write correct
        // amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { base::ioctl_with_mut_ref(self, KVM_CREATE_DEVICE, &mut device) };
        if ret == 0 {
            Ok(
                // SAFETY:
                // Safe because we verify that ret is valid and we own the fd.
                unsafe { SafeDescriptor::from_raw_descriptor(device.fd as i32) },
            )
        } else {
            errno_result()
        }
    }

    fn get_dirty_log(&self, slot: MemSlot, dirty_log: &mut [u8]) -> Result<()> {
        let regions = self.mem_regions.lock();
        let mmap = regions.get(&slot).ok_or_else(|| Error::new(ENOENT))?;
        // Ensures that there are as many bytes in dirty_log as there are pages in the mmap.
        if dirty_log_bitmap_size(mmap.size()) > dirty_log.len() {
            return Err(Error::new(EINVAL));
        }

        let mut dirty_log_kvm = kvm_dirty_log {
            slot,
            ..Default::default()
        };
        dirty_log_kvm.__bindgen_anon_1.dirty_bitmap = dirty_log.as_ptr() as *mut c_void;
        // SAFETY:
        // Safe because the `dirty_bitmap` pointer assigned above is guaranteed to be valid (because
        // it's from a slice) and we checked that it will be large enough to hold the entire log.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DIRTY_LOG, &dirty_log_kvm) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
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
        // KVM delivers IO events in-kernel with ioeventfds, so this is a no-op
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

    fn handle_balloon_event(&mut self, event: BalloonEvent) -> Result<()> {
        match event {
            BalloonEvent::Inflate(m) => self.handle_inflate(m.guest_address, m.size),
            BalloonEvent::Deflate(m) => self.handle_deflate(m.guest_address, m.size),
            BalloonEvent::BalloonTargetReached(_) => Ok(()),
        }
    }
}

impl AsRawDescriptor for KvmVm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vm.as_raw_descriptor()
    }
}

struct KvmVcpuSignalHandle {
    run_mmap: Arc<MemoryMapping>,
}

impl VcpuSignalHandleInner for KvmVcpuSignalHandle {
    fn signal_immediate_exit(&self) {
        // SAFETY: we ensure `run_mmap` is a valid mapping of `kvm_run` at creation time, and the
        // `Arc` ensures the mapping still exists while we hold a reference to it.
        unsafe {
            let run = self.run_mmap.as_ptr() as *mut kvm_run;
            (*run).immediate_exit = 1;
        }
    }
}

/// A wrapper around using a KVM Vcpu.
pub struct KvmVcpu {
    kvm: Kvm,
    vm: SafeDescriptor,
    vcpu: File,
    id: usize,
    cap_kvmclock_ctrl: bool,
    run_mmap: Arc<MemoryMapping>,
}

impl Vcpu for KvmVcpu {
    fn try_clone(&self) -> Result<Self> {
        let vm = self.vm.try_clone()?;
        let vcpu = self.vcpu.try_clone()?;

        Ok(KvmVcpu {
            kvm: self.kvm.try_clone()?,
            vm,
            vcpu,
            cap_kvmclock_ctrl: self.cap_kvmclock_ctrl,
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
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.immediate_exit = exit.into();
    }

    fn signal_handle(&self) -> VcpuSignalHandle {
        VcpuSignalHandle {
            inner: Box::new(KvmVcpuSignalHandle {
                run_mmap: self.run_mmap.clone(),
            }),
        }
    }

    fn on_suspend(&self) -> Result<()> {
        // On KVM implementations that use a paravirtualized clock (e.g. x86), a flag must be set to
        // indicate to the guest kernel that a vCPU was suspended. The guest kernel will use this
        // flag to prevent the soft lockup detection from triggering when this vCPU resumes, which
        // could happen days later in realtime.
        if self.cap_kvmclock_ctrl {
            // SAFETY:
            // The ioctl is safe because it does not read or write memory in this process.
            if unsafe { ioctl(self, KVM_KVMCLOCK_CTRL) } != 0 {
                // Even if the host kernel supports the capability, it may not be configured by
                // the guest - for example, when the guest kernel offlines a CPU.
                if Error::last().errno() != libc::EINVAL {
                    return errno_result();
                }
            }
        }

        Ok(())
    }

    unsafe fn enable_raw_capability(&self, cap: u32, args: &[u64; 4]) -> Result<()> {
        let kvm_cap = kvm_enable_cap {
            cap,
            args: *args,
            ..Default::default()
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct, and because we assume the caller has allocated the args appropriately.
        let ret = ioctl_with_ref(self, KVM_ENABLE_CAP, &kvm_cap);
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    #[allow(clippy::cast_ptr_alignment)]
    // The pointer is page aligned so casting to a different type is well defined, hence the clippy
    // allow attribute.
    fn run(&mut self) -> Result<VcpuExit> {
        // SAFETY:
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN) };
        if ret != 0 {
            return errno_result();
        }

        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };

        // Check for architecture-specific VM exit reasons first in case the architecture wants to
        // override the default handling.
        if let Some(vcpu_exit) = self.handle_vm_exit_arch(run) {
            return Ok(vcpu_exit);
        }

        match run.exit_reason {
            KVM_EXIT_MMIO => Ok(VcpuExit::Mmio),
            KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
            KVM_EXIT_HYPERCALL => Ok(VcpuExit::Hypercall),
            KVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
            KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
            KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown(Ok(()))),
            KVM_EXIT_FAIL_ENTRY => {
                // SAFETY:
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
            KVM_EXIT_INTR => Ok(VcpuExit::Intr),
            KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
            KVM_EXIT_SYSTEM_EVENT => {
                // SAFETY:
                // Safe because we know the exit reason told us this union
                // field is valid
                let event_type = unsafe { run.__bindgen_anon_1.system_event.type_ };
                let event_flags =
                    // SAFETY:
                    // Safe because we know the exit reason told us this union
                    // field is valid
                    unsafe { run.__bindgen_anon_1.system_event.__bindgen_anon_1.flags };
                match event_type {
                    KVM_SYSTEM_EVENT_SHUTDOWN => Ok(VcpuExit::SystemEventShutdown),
                    KVM_SYSTEM_EVENT_RESET => self.system_event_reset(event_flags),
                    KVM_SYSTEM_EVENT_CRASH => Ok(VcpuExit::SystemEventCrash),
                    _ => {
                        error!(
                            "Unknown KVM system event {} with flags {}",
                            event_type, event_flags
                        );
                        Err(Error::new(EINVAL))
                    }
                }
            }
            r => panic!("unknown kvm exit reason: {}", r),
        }
    }

    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Result<()>) -> Result<()> {
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        // Verify that the handler is called in the right context.
        assert!(run.exit_reason == KVM_EXIT_MMIO);
        // SAFETY:
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.
        let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
        let address = mmio.phys_addr;
        let data = &mut mmio.data[..mmio.len as usize];
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

    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams)) -> Result<()> {
        // SAFETY:
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        // Verify that the handler is called in the right context.
        assert!(run.exit_reason == KVM_EXIT_IO);
        // SAFETY:
        // Safe because the exit_reason (which comes from the kernel) told us which
        // union field to use.
        let io = unsafe { run.__bindgen_anon_1.io };
        let address = u64::from(io.port);
        let size = usize::from(io.size);
        let count = io.count as usize;
        let data_len = count * size;
        let data_offset = io.data_offset as usize;
        assert!(data_offset + data_len <= self.run_mmap.size());

        // SAFETY:
        // The data_offset is defined by the kernel to be some number of bytes into the kvm_run
        // structure, which we have fully mmap'd.
        let buffer: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                (run as *mut kvm_run as *mut u8).add(data_offset),
                data_len,
            )
        };
        let data_chunks = buffer.chunks_mut(size);

        if io.direction == KVM_EXIT_IO_IN as u8 {
            for data in data_chunks {
                handle_fn(IoParams {
                    address,
                    operation: IoOperation::Read(data),
                });
            }
        } else {
            debug_assert_eq!(io.direction, KVM_EXIT_IO_OUT as u8);
            for data in data_chunks {
                handle_fn(IoParams {
                    address,
                    operation: IoOperation::Write(data),
                });
            }
        }

        Ok(())
    }
}

impl KvmVcpu {
    /// Gets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_GET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        // SAFETY: trivially safe
        let mut state: kvm_mp_state = unsafe { std::mem::zeroed() };
        let ret = {
            // SAFETY:
            // Safe because we know that our file is a VCPU fd, we know the kernel will only write
            // the correct amount of memory to our pointer, and we verify the return
            // result.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_MP_STATE, &mut state) }
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(state)
    }

    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_SET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    pub fn set_mp_state(&self, state: &kvm_mp_state) -> Result<()> {
        let ret = {
            // SAFETY:
            // The ioctl is safe because the kernel will only read from the kvm_mp_state struct.
            unsafe { ioctl_with_ref(self, KVM_SET_MP_STATE, state) }
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

impl AsRawDescriptor for KvmVcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vcpu.as_raw_descriptor()
    }
}

impl TryFrom<HypervisorCap> for KvmCap {
    type Error = Error;

    fn try_from(cap: HypervisorCap) -> Result<KvmCap> {
        match cap {
            HypervisorCap::ImmediateExit => Ok(KvmCap::ImmediateExit),
            HypervisorCap::UserMemory => Ok(KvmCap::UserMemory),
            #[cfg(target_arch = "x86_64")]
            HypervisorCap::Xcrs => Ok(KvmCap::Xcrs),
            #[cfg(target_arch = "x86_64")]
            HypervisorCap::CalibratedTscLeafRequired => Err(Error::new(libc::EINVAL)),
            HypervisorCap::StaticSwiotlbAllocationRequired => Err(Error::new(libc::EINVAL)),
            HypervisorCap::HypervisorInitializedBootContext => Err(Error::new(libc::EINVAL)),
        }
    }
}

fn to_kvm_irq_routing_entry(item: &IrqRoute, cap_msi_devid: bool) -> kvm_irq_routing_entry {
    match &item.source {
        IrqSource::Irqchip { chip, pin } => kvm_irq_routing_entry {
            gsi: item.gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                irqchip: kvm_irq_routing_irqchip {
                    irqchip: chip_to_kvm_chip(*chip),
                    pin: *pin,
                },
            },
            ..Default::default()
        },
        IrqSource::Msi {
            address,
            data,
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            pci_address,
        } => {
            // Even though we always pass the device ID along to this point, KVM docs say: "If this
            // capability is not available, userspace should never set the KVM_MSI_VALID_DEVID flag
            // as the ioctl might fail"
            let devid = if cap_msi_devid {
                #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
                panic!("unexpected KVM_CAP_MSI_DEVID");
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                Some(pci_address.to_u32())
            } else {
                None
            };
            kvm_irq_routing_entry {
                gsi: item.gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                flags: if devid.is_some() {
                    KVM_MSI_VALID_DEVID
                } else {
                    0
                },
                u: kvm_irq_routing_entry__bindgen_ty_1 {
                    msi: kvm_irq_routing_msi {
                        address_lo: *address as u32,
                        address_hi: (*address >> 32) as u32,
                        data: *data,
                        __bindgen_anon_1: kvm_irq_routing_msi__bindgen_ty_1 {
                            devid: devid.unwrap_or_default(),
                        },
                    },
                },
                ..Default::default()
            }
        }
    }
}

impl From<&kvm_mp_state> for MPState {
    fn from(item: &kvm_mp_state) -> Self {
        match item.mp_state {
            KVM_MP_STATE_RUNNABLE => MPState::Runnable,
            KVM_MP_STATE_UNINITIALIZED => MPState::Uninitialized,
            KVM_MP_STATE_INIT_RECEIVED => MPState::InitReceived,
            KVM_MP_STATE_HALTED => MPState::Halted,
            KVM_MP_STATE_SIPI_RECEIVED => MPState::SipiReceived,
            KVM_MP_STATE_STOPPED => MPState::Stopped,
            state => {
                error!(
                    "unrecognized kvm_mp_state {}, setting to KVM_MP_STATE_RUNNABLE",
                    state
                );
                MPState::Runnable
            }
        }
    }
}

impl From<&MPState> for kvm_mp_state {
    fn from(item: &MPState) -> Self {
        kvm_mp_state {
            mp_state: match item {
                MPState::Runnable => KVM_MP_STATE_RUNNABLE,
                MPState::Uninitialized => KVM_MP_STATE_UNINITIALIZED,
                MPState::InitReceived => KVM_MP_STATE_INIT_RECEIVED,
                MPState::Halted => KVM_MP_STATE_HALTED,
                MPState::SipiReceived => KVM_MP_STATE_SIPI_RECEIVED,
                MPState::Stopped => KVM_MP_STATE_STOPPED,
            },
        }
    }
}
