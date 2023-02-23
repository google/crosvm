// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.
//!
//! New code should use the `hypervisor` crate instead.

#![cfg(unix)]

mod cap;

use std::cell::RefCell;
use std::cmp::min;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::ffi::CString;
use std::fs::File;
use std::mem::size_of;
use std::ops::Deref;
use std::ops::DerefMut;
use std::os::raw::*;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::copy_nonoverlapping;
use std::sync::Arc;

#[allow(unused_imports)]
use base::ioctl;
#[allow(unused_imports)]
use base::ioctl_with_mut_ptr;
#[allow(unused_imports)]
use base::ioctl_with_mut_ref;
#[allow(unused_imports)]
use base::ioctl_with_ptr;
#[allow(unused_imports)]
use base::ioctl_with_ref;
#[allow(unused_imports)]
use base::ioctl_with_val;
#[allow(unused_imports)]
use base::pagesize;
#[allow(unused_imports)]
use base::signal;
use base::sys::BlockedSignal;
#[allow(unused_imports)]
use base::unblock_signal;
#[allow(unused_imports)]
use base::warn;
use base::AsRawDescriptor;
#[allow(unused_imports)]
use base::Error;
#[allow(unused_imports)]
use base::Event;
use base::FromRawDescriptor;
#[allow(unused_imports)]
use base::IoctlNr;
#[allow(unused_imports)]
use base::MappedRegion;
#[allow(unused_imports)]
use base::MemoryMapping;
#[allow(unused_imports)]
use base::MemoryMappingBuilder;
#[allow(unused_imports)]
use base::MmapError;
use base::RawDescriptor;
#[allow(unused_imports)]
use base::Result;
#[allow(unused_imports)]
use base::SIGRTMIN;
use data_model::vec_with_array_field;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use data_model::FlexibleArrayWrapper;
use kvm_sys::*;
use libc::open64;
use libc::sigset_t;
use libc::EBUSY;
use libc::EINVAL;
use libc::ENOENT;
use libc::ENOSPC;
use libc::EOVERFLOW;
use libc::O_CLOEXEC;
use libc::O_RDWR;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

pub use crate::cap::*;

fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

unsafe fn set_user_memory_region<F: AsRawDescriptor>(
    fd: &F,
    slot: u32,
    read_only: bool,
    log_dirty_pages: bool,
    guest_addr: u64,
    memory_size: u64,
    userspace_addr: *mut u8,
) -> Result<()> {
    let mut flags = if read_only { KVM_MEM_READONLY } else { 0 };
    if log_dirty_pages {
        flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }
    let region = kvm_userspace_memory_region {
        slot,
        flags,
        guest_phys_addr: guest_addr,
        memory_size,
        userspace_addr: userspace_addr as u64,
    };

    let ret = ioctl_with_ref(fd, KVM_SET_USER_MEMORY_REGION(), &region);
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

/// A wrapper around opening and using `/dev/kvm`.
///
/// Useful for querying extensions and basic values from the KVM backend. A `Kvm` is required to
/// create a `Vm` object.
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a Kvm object on success.
    pub fn new() -> Result<Kvm> {
        Kvm::new_with_path(&PathBuf::from("/dev/kvm"))
    }

    /// Opens a KVM device at `device_path` and returns a Kvm object on success.
    pub fn new_with_path(device_path: &Path) -> Result<Kvm> {
        // Open calls are safe because we give a nul-terminated string and verify the result.
        let c_path = CString::new(device_path.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { open64(c_path.as_ptr(), O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        // Safe because we verify that ret is valid and we own the fd.
        Ok(Kvm {
            kvm: unsafe { File::from_raw_descriptor(ret) },
        })
    }

    fn check_extension_int(&self, c: Cap) -> i32 {
        // Safe because we know that our file is a KVM fd and that the extension is one of the ones
        // defined by kernel.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c as c_ulong) }
    }

    /// Checks if a particular `Cap` is available.
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) == 1
    }

    /// Gets the size of the mmap required to use vcpu's `kvm_run` structure.
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE()) };
        if res > 0 {
            Ok(res as usize)
        } else {
            errno_result()
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: IoctlNr) -> Result<CpuId> {
        const MAX_KVM_CPUID_ENTRIES: usize = 256;
        let mut cpuid = CpuId::new(MAX_KVM_CPUID_ENTRIES);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(MAX_KVM_CPUID_ENTRIES) above.
            ioctl_with_mut_ptr(self, kind, cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return errno_result();
        }

        Ok(cpuid)
    }

    /// X86 specific call to get the system supported CPUID values
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID())
    }

    /// X86 specific call to get the system emulated CPUID values
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_emulated_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID())
    }

    /// X86 specific call to get list of supported MSRS
    ///
    /// See the documentation for KVM_GET_MSR_INDEX_LIST.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        const MAX_KVM_MSR_ENTRIES: usize = 256;

        let mut msr_list = vec_with_array_field::<kvm_msr_list, u32>(MAX_KVM_MSR_ENTRIES);
        msr_list[0].nmsrs = MAX_KVM_MSR_ENTRIES as u32;

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
            // size (MAX_KVM_MSR_ENTRIES) above.
            ioctl_with_mut_ref(self, KVM_GET_MSR_INDEX_LIST(), &mut msr_list[0])
        };
        if ret < 0 {
            return errno_result();
        }

        let mut nmsrs = msr_list[0].nmsrs;

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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    // The x86 machine type is always 0
    pub fn get_vm_type(&self) -> c_ulong {
        0
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    // Compute the machine type, which should be the IPA range for the VM
    // Ideally, this would take a description of the memory map and return
    // the closest machine type for this VM. Here, we just return the maximum
    // the kernel support.
    #[allow(clippy::useless_conversion)]
    pub fn get_vm_type(&self) -> c_ulong {
        // Safe because we know self is a real kvm fd
        match unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), KVM_CAP_ARM_VM_IPA_SIZE.into()) }
        {
            // Not supported? Use 0 as the machine type, which implies 40bit IPA
            ret if ret < 0 => 0,
            // Use the lower 8 bits representing the IPA space as the machine type
            ipa => (ipa & 0xff) as c_ulong,
        }
    }
}

impl AsRawDescriptor for Kvm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.kvm.as_raw_descriptor()
    }
}

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone, Debug)]
pub enum IoeventAddress {
    Pio(u64),
    Mmio(u64),
}

/// Used in `Vm::register_ioevent` to indicate a size and optionally value to match.
pub enum Datamatch {
    AnyLength,
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
}

/// A source of IRQs in an `IrqRoute`.
pub enum IrqSource {
    Irqchip { chip: u32, pin: u32 },
    Msi { address: u64, data: u32 },
}

/// A single route for an IRQ.
pub struct IrqRoute {
    pub gsi: u32,
    pub source: IrqSource,
}

/// Interrupt controller IDs
pub enum PicId {
    Primary = 0,
    Secondary = 1,
}

/// Number of pins on the IOAPIC.
pub const NUM_IOAPIC_PINS: usize = 24;

// Used to invert the order when stored in a max-heap.
#[derive(Copy, Clone, Eq, PartialEq)]
struct MemSlot(u32);

impl Ord for MemSlot {
    fn cmp(&self, other: &MemSlot) -> Ordering {
        // Notice the order is inverted so the lowest magnitude slot has the highest priority in a
        // max-heap.
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for MemSlot {
    fn partial_cmp(&self, other: &MemSlot) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    vm: File,
    guest_mem: GuestMemory,
    mem_regions: Arc<Mutex<BTreeMap<u32, Box<dyn MappedRegion>>>>,
    mem_slot_gaps: Arc<Mutex<BinaryHeap<MemSlot>>>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm, guest_mem: GuestMemory) -> Result<Vm> {
        // Safe because we know kvm is a real kvm fd as this module is the only one that can make
        // Kvm objects.
        let ret = unsafe { ioctl_with_val(kvm, KVM_CREATE_VM(), kvm.get_vm_type()) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_descriptor(ret) };
            guest_mem.with_regions(|index, guest_addr, size, host_addr, _, _| {
                unsafe {
                    // Safe because the guest regions are guaranteed not to overlap.
                    set_user_memory_region(
                        &vm_file,
                        index as u32,
                        false,
                        false,
                        guest_addr.offset() as u64,
                        size as u64,
                        host_addr as *mut u8,
                    )
                }
            })?;

            Ok(Vm {
                vm: vm_file,
                guest_mem,
                mem_regions: Arc::new(Mutex::new(BTreeMap::new())),
                mem_slot_gaps: Arc::new(Mutex::new(BinaryHeap::new())),
            })
        } else {
            errno_result()
        }
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// This is distinct from the `Kvm` version of this method because the some extensions depend on
    /// the particular `Vm` existence. This method is encouraged by the kernel because it more
    /// accurately reflects the usable capabilities.
    pub fn check_extension(&self, c: Cap) -> bool {
        // Safe because we know that our file is a KVM fd and that the extension is one of the ones
        // defined by kernel.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c as c_ulong) == 1 }
    }

    /// Inserts the given `mem` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the kvm memory mapping is returned on success. The slot can be
    /// given to `Vm::remove_memory_region` to remove the memory from the VM's address space and
    /// take back ownership of `mem`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap with any other memory
    /// slot's region.
    ///
    /// If `read_only` is true, the guest will be able to read the memory as normal, but attempts to
    /// write will trigger a mmio VM exit, leaving the memory untouched.
    ///
    /// If `log_dirty_pages` is true, the slot number can be used to retrieve the pages written to
    /// by the guest with `get_dirty_log`.
    pub fn add_memory_region(
        &mut self,
        guest_addr: GuestAddress,
        mem: Box<dyn MappedRegion>,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<u32> {
        let size = mem.size() as u64;
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
            None => (regions.len() + self.guest_mem.num_regions() as usize) as u32,
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
            gaps.push(MemSlot(slot));
            return Err(e);
        }
        regions.insert(slot, mem);
        Ok(slot)
    }

    /// Removes memory that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_memory_region(&mut self, slot: u32) -> Result<Box<dyn MappedRegion>> {
        let mut regions = self.mem_regions.lock();
        if !regions.contains_key(&slot) {
            return Err(Error::new(ENOENT));
        }
        // Safe because the slot is checked against the list of memory slots.
        unsafe {
            set_user_memory_region(&self.vm, slot, false, false, 0, 0, std::ptr::null_mut())?;
        }
        self.mem_slot_gaps.lock().push(MemSlot(slot));
        // This remove will always succeed because of the contains_key check above.
        Ok(regions.remove(&slot).unwrap())
    }

    /// Gets the bitmap of dirty pages since the last call to `get_dirty_log` for the memory at
    /// `slot`.
    ///
    /// The size of `dirty_log` must be at least as many bits as there are pages in the memory
    /// region `slot` represents. For example, if the size of `slot` is 16 pages, `dirty_log` must
    /// be 2 bytes or greater.
    pub fn get_dirty_log(&self, slot: u32, dirty_log: &mut [u8]) -> Result<()> {
        match self.mem_regions.lock().get(&slot) {
            Some(mem) => {
                // Ensures that there are as many bytes in dirty_log as there are pages in the mmap.
                if dirty_log_bitmap_size(mem.size()) > dirty_log.len() {
                    return Err(Error::new(EINVAL));
                }
                let mut dirty_log_kvm = kvm_dirty_log {
                    slot,
                    ..Default::default()
                };
                dirty_log_kvm.__bindgen_anon_1.dirty_bitmap = dirty_log.as_ptr() as *mut c_void;
                // Safe because the `dirty_bitmap` pointer assigned above is guaranteed to be valid
                // (because it's from a slice) and we checked that it will be large enough to hold
                // the entire log.
                let ret = unsafe { ioctl_with_ref(self, KVM_GET_DIRTY_LOG(), &dirty_log_kvm) };
                if ret == 0 {
                    Ok(())
                } else {
                    errno_result()
                }
            }
            _ => Err(Error::new(ENOENT)),
        }
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any mmio memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    /// Sets the address of a one-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_IDENTITY_MAP_ADDR ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret =
            unsafe { ioctl_with_ref(self, KVM_SET_IDENTITY_MAP_ADDR(), &(addr.offset() as u64)) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the current timestamp of kvmclock as seen by the current guest.
    ///
    /// See the documentation on the KVM_GET_CLOCK ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_clock(&self) -> Result<kvm_clock_data> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write
        // correct amount of memory to our pointer, and we verify the return result.
        let mut clock_data = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_CLOCK(), &mut clock_data) };
        if ret == 0 {
            Ok(clock_data)
        } else {
            errno_result()
        }
    }

    /// Sets the current timestamp of kvmclock to the specified value.
    ///
    /// See the documentation on the KVM_SET_CLOCK ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_clock(&self, clock_data: &kvm_clock_data) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_CLOCK(), clock_data) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Crates an in kernel interrupt controller.
    ///
    /// See the documentation on the KVM_CREATE_IRQCHIP ioctl.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of given interrupt controller by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_pic_state(&self, id: PicId) -> Result<kvm_pic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // PIC (primary or secondary) and not IOAPIC.
                irqchip_state.chip.pic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pic_state(&self, id: PicId, state: &kvm_pic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: id as u32,
            ..Default::default()
        };
        irqchip_state.chip.pic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_ioapic_state(&self) -> Result<kvm_ioapic_state> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // IOAPIC and not PIC.
                irqchip_state.chip.ioapic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_ioapic_state(&self, state: &kvm_ioapic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip {
            chip_id: 2,
            ..Default::default()
        };
        irqchip_state.chip.ioapic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        let mut irq_level = kvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = active.into();

        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQ_LINE(), &irq_level) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn create_pit(&self) -> Result<()> {
        let pit_config = kvm_pit_config::default();
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write
        // correct amount of memory to our pointer, and we verify the return result.
        let mut pit_state = unsafe { std::mem::zeroed() };
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_PIT2(), pit_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit signaling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signaled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    pub fn register_ioevent(
        &self,
        evt: &Event,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, false)
    }

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    pub fn unregister_ioevent(
        &self,
        evt: &Event,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, true)
    }

    fn ioeventfd(
        &self,
        evt: &Event,
        addr: IoeventAddress,
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
            flags |= 1 << kvm_ioeventfd_flag_nr_deassign;
        }
        if do_datamatch {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        if let IoeventAddress::Pio(_) = addr {
            flags |= 1 << kvm_ioeventfd_flag_nr_pio;
        }
        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch_value,
            len: datamatch_len,
            addr: match addr {
                IoeventAddress::Pio(p) => p as u64,
                IoeventAddress::Mmio(m) => m,
            },
            fd: evt.as_raw_descriptor(),
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Registers an event that will, when signalled, trigger the `gsi` irq, and `resample_evt` will
    /// get triggered when the irqchip is resampled.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd_resample(
        &self,
        evt: &Event,
        resample_evt: &Event,
        gsi: u32,
    ) -> Result<()> {
        let irqfd = kvm_irqfd {
            flags: KVM_IRQFD_FLAG_RESAMPLE,
            fd: evt.as_raw_descriptor() as u32,
            resamplefd: resample_evt.as_raw_descriptor() as u32,
            gsi,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Unregisters an event that was previously registered with
    /// `register_irqfd`/`register_irqfd_resample`.
    ///
    /// The `evt` and `gsi` pair must be the same as the ones passed into
    /// `register_irqfd`/`register_irqfd_resample`.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn unregister_irqfd(&self, evt: &Event, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_descriptor() as u32,
            gsi,
            flags: KVM_IRQFD_FLAG_DEASSIGN,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the GSI routing table, replacing any table set with previous calls to
    /// `set_gsi_routing`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_gsi_routing(&self, routes: &[IrqRoute]) -> Result<()> {
        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(routes.len());
        irq_routing[0].nr = routes.len() as u32;

        // Safe because we ensured there is enough space in irq_routing to hold the number of
        // route entries.
        let irq_routes = unsafe { irq_routing[0].entries.as_mut_slice(routes.len()) };
        for (route, irq_route) in routes.iter().zip(irq_routes.iter_mut()) {
            irq_route.gsi = route.gsi;
            match route.source {
                IrqSource::Irqchip { chip, pin } => {
                    irq_route.type_ = KVM_IRQ_ROUTING_IRQCHIP;
                    irq_route.u.irqchip = kvm_irq_routing_irqchip { irqchip: chip, pin }
                }
                IrqSource::Msi { address, data } => {
                    irq_route.type_ = KVM_IRQ_ROUTING_MSI;
                    irq_route.u.msi = kvm_irq_routing_msi {
                        address_lo: address as u32,
                        address_hi: (address >> 32) as u32,
                        data,
                        ..Default::default()
                    }
                }
            }
        }

        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GSI_ROUTING(), &irq_routing[0]) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Enable the specified capability.
    /// See documentation for KVM_ENABLE_CAP.
    /// # Safety
    /// This function is marked as unsafe because `cap` may contain values which are interpreted as
    /// pointers by the kernel.
    pub unsafe fn kvm_enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = ioctl_with_ref(self, KVM_ENABLE_CAP(), cap);
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }
}

impl AsRawDescriptor for Vm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vm.as_raw_descriptor()
    }
}

/// A reason why a VCPU exited. One of these returns every time `Vcpu::run` is called.
#[derive(Debug)]
pub enum VcpuExit {
    /// An out port instruction was run on the given port with the given data.
    IoOut {
        port: u16,
        size: usize,
        data: [u8; 8],
    },
    /// An in port instruction was run on the given port.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    IoIn {
        port: u16,
        size: usize,
    },
    /// A read instruction was run against the given MMIO address.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    MmioRead {
        address: u64,
        size: usize,
    },
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite {
        address: u64,
        size: usize,
        data: [u8; 8],
    },
    IoapicEoi {
        vector: u8,
    },
    HypervSynic {
        msr: u32,
        control: u64,
        evt_page: u64,
        msg_page: u64,
    },
    HypervHcall {
        input: u64,
        params: [u64; 2],
    },
    Unknown,
    Exception,
    Hypercall,
    Debug,
    Hlt,
    IrqWindowOpen,
    Shutdown,
    FailEntry {
        hardware_entry_failure_reason: u64,
    },
    Intr,
    SetTpr,
    TprAccess,
    S390Sieic,
    S390Reset,
    Dcr,
    Nmi,
    InternalError,
    Osi,
    PaprHcall,
    S390Ucontrol,
    Watchdog,
    S390Tsch,
    Epr,
    /// The cpu triggered a system level event which is specified by the type field.
    /// The first field is the event type and the second field is flags.
    /// The possible event types are shutdown, reset, or crash.  So far there
    /// are not any flags defined.
    SystemEvent(u32 /* event_type */, u64 /* flags */),
}

/// A wrapper around creating and using a VCPU.
/// `Vcpu` provides all functionality except for running. To run, `to_runnable` must be called to
/// lock the vcpu to a thread. Then the returned `RunnableVcpu` can be used for running.
pub struct Vcpu {
    vcpu: File,
    run_mmap: MemoryMapping,
}

pub struct VcpuThread {
    run: *mut kvm_run,
    signal_num: Option<c_int>,
}

thread_local!(static VCPU_THREAD: RefCell<Option<VcpuThread>> = RefCell::new(None));

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    pub fn new(id: c_ulong, kvm: &Kvm, vm: &Vm) -> Result<Vcpu> {
        let run_mmap_size = kvm.get_vcpu_mmap_size()?;

        // Safe because we know that vm a VM fd and we verify the return result.
        let vcpu_fd = unsafe { ioctl_with_val(vm, KVM_CREATE_VCPU(), id) };
        if vcpu_fd < 0 {
            return errno_result();
        }

        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_descriptor(vcpu_fd) };

        let run_mmap = MemoryMappingBuilder::new(run_mmap_size)
            .from_file(&vcpu)
            .build()
            .map_err(|_| Error::new(ENOSPC))?;

        Ok(Vcpu { vcpu, run_mmap })
    }

    /// Consumes `self` and returns a `RunnableVcpu`. A `RunnableVcpu` is required to run the
    /// guest.
    /// Assigns a vcpu to the current thread and stores it in a hash map that can be used by signal
    /// handlers to call set_local_immediate_exit(). An optional signal number will be temporarily
    /// blocked while assigning the vcpu to the thread and later blocked when `RunnableVcpu` is
    /// destroyed.
    ///
    /// Returns an error, `EBUSY`, if the current thread already contains a Vcpu.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn to_runnable(self, signal_num: Option<c_int>) -> Result<RunnableVcpu> {
        // Block signal while we add -- if a signal fires (very unlikely,
        // as this means something is trying to pause the vcpu before it has
        // even started) it'll try to grab the read lock while this write
        // lock is grabbed and cause a deadlock.
        // Assuming that a failure to block means it's already blocked.
        let _blocked_signal = signal_num.map(BlockedSignal::new);

        VCPU_THREAD.with(|v| {
            if v.borrow().is_none() {
                *v.borrow_mut() = Some(VcpuThread {
                    run: self.run_mmap.as_ptr() as *mut kvm_run,
                    signal_num,
                });
                Ok(())
            } else {
                Err(Error::new(EBUSY))
            }
        })?;

        Ok(RunnableVcpu {
            vcpu: self,
            phantom: Default::default(),
        })
    }

    /// Sets the data received by a mmio read, ioport in, or hypercall instruction.
    ///
    /// This function should be called after `Vcpu::run` returns an `VcpuExit::IoIn`,
    /// `VcpuExit::MmioRead`, or 'VcpuExit::HypervHcall`.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn set_data(&self, data: &[u8]) -> Result<()> {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        match run.exit_reason {
            KVM_EXIT_IO => {
                let run_start = run as *mut kvm_run as *mut u8;
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let io = unsafe { run.__bindgen_anon_1.io };
                if io.direction as u32 != KVM_EXIT_IO_IN {
                    return Err(Error::new(EINVAL));
                }
                let data_size = (io.count as usize) * (io.size as usize);
                if data_size != data.len() {
                    return Err(Error::new(EINVAL));
                }
                // The data_offset is defined by the kernel to be some number of bytes into the
                // kvm_run structure, which we have fully mmap'd.
                unsafe {
                    let data_ptr = run_start.offset(io.data_offset as isize);
                    copy_nonoverlapping(data.as_ptr(), data_ptr, data_size);
                }
                Ok(())
            }
            KVM_EXIT_MMIO => {
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                if mmio.is_write != 0 {
                    return Err(Error::new(EINVAL));
                }
                let len = mmio.len as usize;
                if len != data.len() {
                    return Err(Error::new(EINVAL));
                }
                mmio.data[..len].copy_from_slice(data);
                Ok(())
            }
            KVM_EXIT_HYPERV => {
                // Safe because the exit_reason (which comes from the kernel) told us which
                // union field to use.
                let hyperv = unsafe { &mut run.__bindgen_anon_1.hyperv };
                if hyperv.type_ != KVM_EXIT_HYPERV_HCALL {
                    return Err(Error::new(EINVAL));
                }
                let hcall = unsafe { &mut hyperv.u.hcall };
                match data.try_into() {
                    Ok(data) => {
                        hcall.result = u64::from_ne_bytes(data);
                    }
                    _ => return Err(Error::new(EINVAL)),
                }
                Ok(())
            }
            _ => Err(Error::new(EINVAL)),
        }
    }

    /// Sets the bit that requests an immediate exit.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn set_immediate_exit(&self, exit: bool) {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was. The pointer is page aligned so casting to a different
        // type is well defined, hence the clippy allow attribute.
        let run = unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) };
        run.immediate_exit = exit.into();
    }

    /// Sets/clears the bit for immediate exit for the vcpu on the current thread.
    pub fn set_local_immediate_exit(exit: bool) {
        VCPU_THREAD.with(|v| {
            if let Some(state) = &(*v.borrow()) {
                unsafe {
                    (*state.run).immediate_exit = exit.into();
                };
            }
        });
    }

    /// Gets the VCPU registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(regs)
    }

    /// Sets the VCPU registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the VCPU special registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(regs)
    }

    /// Sets the VCPU special registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), sregs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the VCPU FPU registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(regs)
    }

    /// X86 specific call to setup the FPU
    ///
    /// See the documentation for KVM_SET_FPU.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_FPU(), fpu)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the VCPU debug registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_debugregs(&self) -> Result<kvm_debugregs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_DEBUGREGS(), &mut regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(regs)
    }

    /// Sets the VCPU debug registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_debugregs(&self, dregs: &kvm_debugregs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_DEBUGREGS(), dregs)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the VCPU extended control registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_xcrs(&self) -> Result<kvm_xcrs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_XCRS(), &mut regs) };
        if ret != 0 {
            return errno_result();
        }
        Ok(regs)
    }

    /// Sets the VCPU extended control registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_xcrs struct.
            ioctl_with_ref(self, KVM_SET_XCRS(), xcrs)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// X86 specific call to get the MSRS
    ///
    /// See the documentation for KVM_SET_MSRS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msr_entries: &mut Vec<kvm_msr_entry>) -> Result<()> {
        let mut msrs = vec_with_array_field::<kvm_msrs, kvm_msr_entry>(msr_entries.len());
        unsafe {
            // Mapping the unsized array to a slice is unsafe because the length isn't known.
            // Providing the length used to create the struct guarantees the entire slice is valid.
            let entries: &mut [kvm_msr_entry] = msrs[0].entries.as_mut_slice(msr_entries.len());
            entries.copy_from_slice(msr_entries);
        }
        msrs[0].nmsrs = msr_entries.len() as u32;
        let ret = unsafe {
            // Here we trust the kernel not to read or write past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_GET_MSRS(), &msrs[0])
        };
        if ret < 0 {
            // KVM_SET_MSRS actually returns the number of msr entries written.
            return errno_result();
        }
        unsafe {
            let count = ret as usize;
            assert!(count <= msr_entries.len());
            let entries: &mut [kvm_msr_entry] = msrs[0].entries.as_mut_slice(count);
            msr_entries.truncate(count);
            msr_entries.copy_from_slice(entries);
        }
        Ok(())
    }

    /// X86 specific call to setup the MSRS
    ///
    /// See the documentation for KVM_SET_MSRS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_msrs(&self, msrs: &kvm_msrs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_SET_MSRS(), msrs)
        };
        if ret < 0 {
            // KVM_SET_MSRS actually returns the number of msr entries written.
            return errno_result();
        }
        Ok(())
    }

    /// X86 specific call to setup the CPUID registers
    ///
    /// See the documentation for KVM_SET_CPUID2.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_ptr())
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// X86 specific call to get the system emulated hyper-v CPUID values
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_hyperv_cpuid(&self) -> Result<CpuId> {
        const MAX_KVM_CPUID_ENTRIES: usize = 256;
        let mut cpuid = CpuId::new(MAX_KVM_CPUID_ENTRIES);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(MAX_KVM_CPUID_ENTRIES) above.
            ioctl_with_mut_ptr(self, KVM_GET_SUPPORTED_HV_CPUID(), cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(cpuid)
    }

    /// X86 specific call to get the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_GET_LAPIC.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic: kvm_lapic_state = Default::default();

        let ret = unsafe {
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(klapic)
    }

    /// X86 specific call to set the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_SET_LAPIC.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the klapic struct.
            ioctl_with_ref(self, KVM_SET_LAPIC(), klapic)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_GET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only
        // write correct amount of memory to our pointer, and we verify the return result.
        let mut state: kvm_mp_state = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_MP_STATE(), &mut state) };
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_mp_state(&self, state: &kvm_mp_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the kvm_mp_state struct.
            ioctl_with_ref(self, KVM_SET_MP_STATE(), state)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_GET_VCPU_EVENTS.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        // Safe because we know that our file is a VCPU fd, we know the kernel
        // will only write correct amount of memory to our pointer, and we
        // verify the return result.
        let mut events: kvm_vcpu_events = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_VCPU_EVENTS(), &mut events) };
        if ret < 0 {
            return errno_result();
        }
        Ok(events)
    }

    /// Sets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_SET_VCPU_EVENTS.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_vcpu_events(&self, events: &kvm_vcpu_events) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the
            // kvm_vcpu_events.
            ioctl_with_ref(self, KVM_SET_VCPU_EVENTS(), events)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Enable the specified capability.
    /// See documentation for KVM_ENABLE_CAP.
    /// # Safety
    /// This function is marked as unsafe because `cap` may contain values which are interpreted as
    /// pointers by the kernel.
    pub unsafe fn kvm_enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = ioctl_with_ref(self, KVM_ENABLE_CAP(), cap);
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Specifies set of signals that are blocked during execution of KVM_RUN.
    /// Signals that are not blocked will cause KVM_RUN to return with -EINTR.
    ///
    /// See the documentation for KVM_SET_SIGNAL_MASK
    pub fn set_signal_mask(&self, signals: &[c_int]) -> Result<()> {
        let sigset = signal::create_sigset(signals)?;

        let mut kvm_sigmask = vec_with_array_field::<kvm_signal_mask, sigset_t>(1);
        // Rust definition of sigset_t takes 128 bytes, but the kernel only
        // expects 8-bytes structure, so we can't write
        // kvm_sigmask.len  = size_of::<sigset_t>() as u32;
        kvm_sigmask[0].len = 8;
        // Ensure the length is not too big.
        const _ASSERT: usize = size_of::<sigset_t>() - 8usize;

        // Safe as we allocated exactly the needed space
        unsafe {
            copy_nonoverlapping(
                &sigset as *const sigset_t as *const u8,
                kvm_sigmask[0].sigset.as_mut_ptr(),
                8,
            );
        }

        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the
            // kvm_signal_mask structure.
            ioctl_with_ref(self, KVM_SET_SIGNAL_MASK(), &kvm_sigmask[0])
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Sets the value of one register on this VCPU.  The id of the register is
    /// encoded as specified in the kernel documentation for KVM_SET_ONE_REG.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()> {
        let data_ref = &data as *const u64;
        let onereg = kvm_one_reg {
            id: reg_id,
            addr: data_ref as u64,
        };
        // safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

impl AsRawDescriptor for Vcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vcpu.as_raw_descriptor()
    }
}

/// A Vcpu that has a thread and can be run. Created by calling `to_runnable` on a `Vcpu`.
/// Implements `Deref` to a `Vcpu` so all `Vcpu` methods are usable, with the addition of the `run`
/// function to execute the guest.
pub struct RunnableVcpu {
    vcpu: Vcpu,
    // vcpus must stay on the same thread once they start.
    // Add the PhantomData pointer to ensure RunnableVcpu is not `Send`.
    phantom: std::marker::PhantomData<*mut u8>,
}

impl RunnableVcpu {
    /// Runs the VCPU until it exits, returning the reason for the exit.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    #[allow(clippy::cast_ptr_alignment)]
    // The pointer is page aligned so casting to a different type is well defined, hence the clippy
    // allow attribute.
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            // Safe because we know we mapped enough memory to hold the kvm_run struct because the
            // kernel told us how large it was.
            let run = unsafe { &*(self.run_mmap.as_ptr() as *const kvm_run) };
            match run.exit_reason {
                KVM_EXIT_IO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port = io.port;
                    let size = (io.count as usize) * (io.size as usize);
                    match io.direction as u32 {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn { port, size }),
                        KVM_EXIT_IO_OUT => {
                            let mut data = [0; 8];
                            let run_start = run as *const kvm_run as *const u8;
                            // The data_offset is defined by the kernel to be some number of bytes
                            // into the kvm_run structure, which we have fully mmap'd.
                            unsafe {
                                let data_ptr = run_start.offset(io.data_offset as isize);
                                copy_nonoverlapping(
                                    data_ptr,
                                    data.as_mut_ptr(),
                                    min(size, data.len()),
                                );
                            }
                            Ok(VcpuExit::IoOut { port, size, data })
                        }
                        _ => Err(Error::new(EINVAL)),
                    }
                }
                KVM_EXIT_MMIO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let mmio = unsafe { &run.__bindgen_anon_1.mmio };
                    let address = mmio.phys_addr;
                    let size = min(mmio.len as usize, mmio.data.len());
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite {
                            address,
                            size,
                            data: mmio.data,
                        })
                    } else {
                        Ok(VcpuExit::MmioRead { address, size })
                    }
                }
                KVM_EXIT_IOAPIC_EOI => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let vector = unsafe { run.__bindgen_anon_1.eoi.vector };
                    Ok(VcpuExit::IoapicEoi { vector })
                }
                KVM_EXIT_HYPERV => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let hyperv = unsafe { &run.__bindgen_anon_1.hyperv };
                    match hyperv.type_ as u32 {
                        KVM_EXIT_HYPERV_SYNIC => {
                            let synic = unsafe { &hyperv.u.synic };
                            Ok(VcpuExit::HypervSynic {
                                msr: synic.msr,
                                control: synic.control,
                                evt_page: synic.evt_page,
                                msg_page: synic.msg_page,
                            })
                        }
                        KVM_EXIT_HYPERV_HCALL => {
                            let hcall = unsafe { &hyperv.u.hcall };
                            Ok(VcpuExit::HypervHcall {
                                input: hcall.input,
                                params: hcall.params,
                            })
                        }
                        _ => Err(Error::new(EINVAL)),
                    }
                }
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_HYPERCALL => Ok(VcpuExit::Hypercall),
                KVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => {
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
                KVM_EXIT_SET_TPR => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT => {
                    // Safe because we know the exit reason told us this union
                    // field is valid
                    let event_type = unsafe { run.__bindgen_anon_1.system_event.type_ };
                    let event_flags =
                        unsafe { run.__bindgen_anon_1.system_event.__bindgen_anon_1.flags };
                    Ok(VcpuExit::SystemEvent(event_type, event_flags))
                }
                r => panic!("unknown kvm exit reason: {}", r),
            }
        } else {
            errno_result()
        }
    }
}

impl Deref for RunnableVcpu {
    type Target = Vcpu;
    fn deref(&self) -> &Self::Target {
        &self.vcpu
    }
}

impl DerefMut for RunnableVcpu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vcpu
    }
}

impl AsRawDescriptor for RunnableVcpu {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.vcpu.as_raw_descriptor()
    }
}

impl Drop for RunnableVcpu {
    fn drop(&mut self) {
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
}

/// Wrapper for kvm_cpuid2 which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type CpuId = FlexibleArrayWrapper<kvm_cpuid2, kvm_cpuid_entry2>;
