// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.

mod cap;

use std::cmp::{min, Ordering};
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::mem::size_of;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::copy_nonoverlapping;

use libc::sigset_t;
use libc::{open, EINVAL, ENOENT, ENOSPC, O_CLOEXEC, O_RDWR};

use kvm_sys::*;

use msg_socket::MsgOnSocket;
#[allow(unused_imports)]
use sys_util::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
    pagesize, signal, warn, Error, EventFd, GuestAddress, GuestMemory, MemoryMapping,
    MemoryMappingArena, Result,
};

pub use crate::cap::*;

fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

// Returns a `Vec<T>` with a size in ytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

unsafe fn set_user_memory_region<F: AsRawFd>(
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
        // Open calls are safe because we give a constant nul-terminated string and verify the
        // result.
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        // Safe because we verify that ret is valid and we own the fd.
        Ok(Kvm {
            kvm: unsafe { File::from_raw_fd(ret) },
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
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE() as c_ulong) };
        if res > 0 {
            Ok(res as usize)
        } else {
            errno_result()
        }
    }

    /// Gets the recommended maximum number of VCPUs per VM.
    pub fn get_nr_vcpus(&self) -> u32 {
        match self.check_extension_int(Cap::NrVcpus) {
            0 => 4, // according to api.txt
            x if x > 0 => x as u32,
            _ => {
                warn!("kernel returned invalid number of VCPUs");
                4
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: u64) -> Result<CpuId> {
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
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone, Debug, MsgOnSocket)]
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
    device_memory: HashMap<u32, MemoryMapping>,
    mmap_arenas: HashMap<u32, MemoryMappingArena>,
    mem_slot_gaps: BinaryHeap<MemSlot>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm, guest_mem: GuestMemory) -> Result<Vm> {
        // Safe because we know kvm is a real kvm fd as this module is the only one that can make
        // Kvm objects.
        let ret = unsafe { ioctl(kvm, KVM_CREATE_VM()) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            guest_mem.with_regions(|index, guest_addr, size, host_addr, _| {
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
                device_memory: HashMap::new(),
                mmap_arenas: HashMap::new(),
                mem_slot_gaps: BinaryHeap::new(),
            })
        } else {
            errno_result()
        }
    }

    // Helper method for `set_user_memory_region` that tracks available slots.
    unsafe fn set_user_memory_region(
        &mut self,
        read_only: bool,
        log_dirty_pages: bool,
        guest_addr: u64,
        memory_size: u64,
        userspace_addr: *mut u8,
    ) -> Result<u32> {
        let slot = match self.mem_slot_gaps.pop() {
            Some(gap) => gap.0,
            None => {
                (self.device_memory.len()
                    + self.guest_mem.num_regions() as usize
                    + self.mmap_arenas.len()) as u32
            }
        };

        let res = set_user_memory_region(
            &self.vm,
            slot,
            read_only,
            log_dirty_pages,
            guest_addr,
            memory_size,
            userspace_addr,
        );
        match res {
            Ok(_) => Ok(slot),
            Err(e) => {
                self.mem_slot_gaps.push(MemSlot(slot));
                Err(e)
            }
        }
    }

    // Helper method for `set_user_memory_region` that tracks available slots.
    unsafe fn remove_user_memory_region(&mut self, slot: u32) -> Result<()> {
        set_user_memory_region(&self.vm, slot, false, false, 0, 0, std::ptr::null_mut())?;
        self.mem_slot_gaps.push(MemSlot(slot));
        Ok(())
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

    /// Inserts the given `MemoryMapping` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the device memory mapping is returned on success. The slot can be
    /// given to `Vm::remove_device_memory` to remove the memory from the VM's address space and
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
    pub fn add_device_memory(
        &mut self,
        guest_addr: GuestAddress,
        mem: MemoryMapping,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<u32> {
        if guest_addr < self.guest_mem.end_addr() {
            return Err(Error::new(ENOSPC));
        }

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        let slot = unsafe {
            self.set_user_memory_region(
                read_only,
                log_dirty_pages,
                guest_addr.offset() as u64,
                mem.size() as u64,
                mem.as_ptr(),
            )?
        };
        self.device_memory.insert(slot, mem);

        Ok(slot)
    }

    /// Removes device memory that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_device_memory(&mut self, slot: u32) -> Result<MemoryMapping> {
        if self.device_memory.contains_key(&slot) {
            // Safe because the slot is checked against the list of device memory slots.
            unsafe {
                self.remove_user_memory_region(slot)?;
            }
            // Safe to unwrap since map is checked to contain key
            Ok(self.device_memory.remove(&slot).unwrap())
        } else {
            Err(Error::new(ENOENT))
        }
    }

    /// Inserts the given `MemoryMappingArena` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the device memory mapping is returned on success. The slot can be
    /// given to `Vm::remove_mmap_arena` to remove the memory from the VM's address space and
    /// take back ownership of `mmap_arena`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap with any other memory
    /// slot's region.
    ///
    /// If `read_only` is true, the guest will be able to read the memory as normal, but attempts to
    /// write will trigger a mmio VM exit, leaving the memory untouched.
    ///
    /// If `log_dirty_pages` is true, the slot number can be used to retrieve the pages written to
    /// by the guest with `get_dirty_log`.
    pub fn add_mmap_arena(
        &mut self,
        guest_addr: GuestAddress,
        mmap_arena: MemoryMappingArena,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<u32> {
        if guest_addr < self.guest_mem.end_addr() {
            return Err(Error::new(ENOSPC));
        }

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        let slot = unsafe {
            self.set_user_memory_region(
                read_only,
                log_dirty_pages,
                guest_addr.offset() as u64,
                mmap_arena.size() as u64,
                mmap_arena.as_ptr(),
            )?
        };
        self.mmap_arenas.insert(slot, mmap_arena);

        Ok(slot)
    }

    /// Removes memory map arena that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_mmap_arena(&mut self, slot: u32) -> Result<MemoryMappingArena> {
        if self.mmap_arenas.contains_key(&slot) {
            // Safe because the slot is checked against the list of device memory slots.
            unsafe {
                self.remove_user_memory_region(slot)?;
            }
            // Safe to unwrap since map is checked to contain key
            Ok(self.mmap_arenas.remove(&slot).unwrap())
        } else {
            Err(Error::new(ENOENT))
        }
    }

    /// Get a mutable reference to the memory map arena added at the given slot.
    pub fn get_mmap_arena(&mut self, slot: u32) -> Option<&mut MemoryMappingArena> {
        self.mmap_arenas.get_mut(&slot)
    }

    /// Gets the bitmap of dirty pages since the last call to `get_dirty_log` for the memory at
    /// `slot`.
    ///
    /// The size of `dirty_log` must be at least as many bits as there are pages in the memory
    /// region `slot` represents. For example, if the size of `slot` is 16 pages, `dirty_log` must
    /// be 2 bytes or greater.
    pub fn get_dirty_log(&self, slot: u32, dirty_log: &mut [u8]) -> Result<()> {
        match self.device_memory.get(&slot) {
            Some(mmap) => {
                // Ensures that there are as many bytes in dirty_log as there are pages in the mmap.
                if dirty_log_bitmap_size(mmap.size()) > dirty_log.len() {
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
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_TSS_ADDR ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tss_addr(&self, addr: GuestAddress) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), addr.offset() as u64) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
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
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = id as u32;
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
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = id as u32;
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
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = 2;
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
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = 2;
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
        irq_level.level = if active { 1 } else { 0 };

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
        evt: &EventFd,
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
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, true)
    }

    fn ioeventfd(
        &self,
        evt: &EventFd,
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
            fd: evt.as_raw_fd(),
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

    /// Registers an event that will, when signalled, trigger the `gsi` irq.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_fd() as u32,
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
        evt: &EventFd,
        resample_evt: &EventFd,
        gsi: u32,
    ) -> Result<()> {
        let irqfd = kvm_irqfd {
            flags: KVM_IRQFD_FLAG_RESAMPLE,
            fd: evt.as_raw_fd() as u32,
            resamplefd: resample_evt.as_raw_fd() as u32,
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
    pub fn unregister_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_fd() as u32,
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

    /// Does KVM_CREATE_DEVICE for a generic device.
    pub fn create_device(&self, device: &mut kvm_create_device) -> Result<()> {
        let ret = unsafe { sys_util::ioctl_with_ref(self, KVM_CREATE_DEVICE(), device) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// This queries the kernel for the preferred target CPU type.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn arm_preferred_target(&self, kvi: &mut kvm_vcpu_init) -> Result<()> {
        // The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_ARM_PREFERRED_TARGET(), kvi) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Enable the specified capability.
    /// See documentation for KVM_ENABLE_CAP.
    pub fn kvm_enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), cap) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }

    /// (x86-only): Enable support for split-irqchip.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn enable_split_irqchip(&self) -> Result<()> {
        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = NUM_IOAPIC_PINS as u64;
        self.kvm_enable_cap(&cap)
    }

    /// Request that the kernel inject the specified MSI message.
    /// Returns Ok(true) on delivery, Ok(false) if the guest blocked delivery, or an error.
    /// See kernel documentation for KVM_SIGNAL_MSI.
    pub fn signal_msi(&self, msi: &kvm_msi) -> Result<bool> {
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_SIGNAL_MSI(), msi) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(ret > 0)
        }
    }
}

impl AsRawFd for Vm {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
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
    Unknown,
    Exception,
    Hypercall,
    Debug,
    Hlt,
    IrqWindowOpen,
    Shutdown,
    FailEntry,
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
pub struct Vcpu {
    vcpu: File,
    run_mmap: MemoryMapping,
    guest_mem: GuestMemory,
}

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
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let run_mmap =
            MemoryMapping::from_fd(&vcpu, run_mmap_size).map_err(|_| Error::new(ENOSPC))?;

        let guest_mem = vm.guest_mem.clone();

        Ok(Vcpu {
            vcpu,
            run_mmap,
            guest_mem,
        })
    }

    /// Gets a reference to the guest memory owned by this VM of this VCPU.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    /// Sets the data received by an mmio or ioport read/in instruction.
    ///
    /// This function should be called after `Vcpu::run` returns an `VcpuExit::IoIn` or
    /// `Vcpu::MmioRead`.
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
            _ => Err(Error::new(EINVAL)),
        }
    }

    /// Runs the VCPU until it exits, returning the reason.
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
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_HYPERCALL => Ok(VcpuExit::Hypercall),
                KVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => Ok(VcpuExit::FailEntry),
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
                    let event_flags = unsafe { run.__bindgen_anon_1.system_event.flags };
                    Ok(VcpuExit::SystemEvent(event_type, event_flags))
                }
                r => panic!("unknown kvm exit reason: {}", r),
            }
        } else {
            errno_result()
        }
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
            entries.copy_from_slice(&msr_entries);
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
            msr_entries.copy_from_slice(&entries);
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

    /// Signals to the host kernel that this VCPU is about to be paused.
    ///
    /// See the documentation for KVM_KVMCLOCK_CTRL.
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because it does not read or write memory in this process.
            ioctl(self, KVM_KVMCLOCK_CTRL())
        };

        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Specifies set of signals that are blocked during execution of KVM_RUN.
    /// Signals that are not blocked will will cause KVM_RUN to return
    /// with -EINTR.
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
        const _ASSERT: usize = size_of::<sigset_t>() - 8 as usize;

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
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// This initializes an ARM VCPU to the specified type with the specified features
    /// and resets the values of all of its registers to defaults.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn arm_vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT(), kvi) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Use the KVM_INTERRUPT ioctl to inject the specified interrupt vector.
    ///
    /// While this ioctl exits on PPC and MIPS as well as x86, the semantics are different and
    /// ChromeOS doesn't support PPC or MIPS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn interrupt(&self, irq: u32) -> Result<()> {
        let interrupt = kvm_interrupt { irq };
        // safe becuase we allocated the struct and we know the kernel will read
        // exactly the size of the struct
        let ret = unsafe { ioctl_with_ref(self, KVM_INTERRUPT(), &interrupt) };
        if ret < 0 {
            errno_result()
        } else {
            Ok(())
        }
    }
}

impl AsRawFd for Vcpu {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

/// Wrapper for kvm_cpuid2 which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    kvm_cpuid: Vec<kvm_cpuid2>,
    allocated_len: usize, // Number of kvm_cpuid_entry2 structs at the end of kvm_cpuid2.
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Get the entries slice so they can be modified before passing to the VCPU.
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        &mut self.kvm_cpuid[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_log_size() {
        let page_size = pagesize();
        assert_eq!(dirty_log_bitmap_size(0), 0);
        assert_eq!(dirty_log_bitmap_size(page_size), 1);
        assert_eq!(dirty_log_bitmap_size(page_size * 8), 1);
        assert_eq!(dirty_log_bitmap_size(page_size * 8 + 1), 2);
        assert_eq!(dirty_log_bitmap_size(page_size * 100), 13);
    }

    #[test]
    fn new() {
        Kvm::new().unwrap();
    }

    #[test]
    fn create_vm() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        Vm::new(&kvm, gm).unwrap();
    }

    #[test]
    fn check_extension() {
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::UserMemory));
        // I assume nobody is testing this on s390
        assert!(!kvm.check_extension(Cap::S390UserSigp));
    }

    #[test]
    fn check_vm_extension() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        assert!(vm.check_extension(Cap::UserMemory));
        // I assume nobody is testing this on s390
        assert!(!vm.check_extension(Cap::S390UserSigp));
    }

    #[test]
    fn get_supported_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_supported_cpuid().unwrap();
        let cpuid_entries = cpuid.mut_entries_slice();
        assert!(cpuid_entries.len() > 0);
    }

    #[test]
    fn get_emulated_cpuid() {
        let kvm = Kvm::new().unwrap();
        kvm.get_emulated_cpuid().unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msr_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_list = kvm.get_msr_index_list().unwrap();
        assert!(msr_list.len() >= 2);
    }

    #[test]
    fn add_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x1000), mem, false, false)
            .unwrap();
    }

    #[test]
    fn add_memory_ro() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x1000), mem, true, false)
            .unwrap();
    }

    #[test]
    fn remove_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        let mem_ptr = mem.as_ptr();
        let slot = vm
            .add_device_memory(GuestAddress(0x1000), mem, false, false)
            .unwrap();
        let mem = vm.remove_device_memory(slot).unwrap();
        assert_eq!(mem.size(), mem_size);
        assert_eq!(mem.as_ptr(), mem_ptr);
    }

    #[test]
    fn remove_invalid_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        assert!(vm.remove_device_memory(0).is_err());
    }

    #[test]
    fn overlap_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x2000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        assert!(vm
            .add_device_memory(GuestAddress(0x2000), mem, false, false)
            .is_err());
    }

    #[test]
    fn get_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let obj_addr = GuestAddress(0xf0);
        vm.get_memory().write_obj_at_addr(67u8, obj_addr).unwrap();
        let read_val: u8 = vm.get_memory().read_obj_from_addr(obj_addr).unwrap();
        assert_eq!(read_val, 67u8);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn clock_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let mut clock_data = vm.get_clock().unwrap();
        clock_data.clock += 1000;
        vm.set_clock(&clock_data).unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn pic_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        let pic_state = vm.get_pic_state(PicId::Secondary).unwrap();
        vm.set_pic_state(PicId::Secondary, &pic_state).unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn ioapic_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        let ioapic_state = vm.get_ioapic_state().unwrap();
        vm.set_ioapic_state(&ioapic_state).unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn pit_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        vm.create_pit().unwrap();
        let pit_state = vm.get_pit_state().unwrap();
        vm.set_pit_state(&pit_state).unwrap();
    }

    #[test]
    fn register_ioevent() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd = EventFd::new().unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
            .unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
            .unwrap();
        vm.register_ioevent(
            &evtfd,
            IoeventAddress::Pio(0xc1),
            Datamatch::U8(Some(0x7fu8)),
        )
        .unwrap();
        vm.register_ioevent(
            &evtfd,
            IoeventAddress::Pio(0xc2),
            Datamatch::U16(Some(0x1337u16)),
        )
        .unwrap();
        vm.register_ioevent(
            &evtfd,
            IoeventAddress::Pio(0xc4),
            Datamatch::U32(Some(0xdeadbeefu32)),
        )
        .unwrap();
        vm.register_ioevent(
            &evtfd,
            IoeventAddress::Pio(0xc8),
            Datamatch::U64(Some(0xdeadbeefdeadbeefu64)),
        )
        .unwrap();
    }

    #[test]
    fn unregister_ioevent() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd = EventFd::new().unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
            .unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
            .unwrap();
        vm.register_ioevent(
            &evtfd,
            IoeventAddress::Mmio(0x1004),
            Datamatch::U8(Some(0x7fu8)),
        )
        .unwrap();
        vm.unregister_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
            .unwrap();
        vm.unregister_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
            .unwrap();
        vm.unregister_ioevent(
            &evtfd,
            IoeventAddress::Mmio(0x1004),
            Datamatch::U8(Some(0x7fu8)),
        )
        .unwrap();
    }

    #[test]
    fn register_irqfd() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd1 = EventFd::new().unwrap();
        let evtfd2 = EventFd::new().unwrap();
        let evtfd3 = EventFd::new().unwrap();
        vm.register_irqfd(&evtfd1, 4).unwrap();
        vm.register_irqfd(&evtfd2, 8).unwrap();
        vm.register_irqfd(&evtfd3, 4).unwrap();
        vm.register_irqfd(&evtfd3, 4).unwrap_err();
    }

    #[test]
    fn unregister_irqfd() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd1 = EventFd::new().unwrap();
        let evtfd2 = EventFd::new().unwrap();
        let evtfd3 = EventFd::new().unwrap();
        vm.register_irqfd(&evtfd1, 4).unwrap();
        vm.register_irqfd(&evtfd2, 8).unwrap();
        vm.register_irqfd(&evtfd3, 4).unwrap();
        vm.unregister_irqfd(&evtfd1, 4).unwrap();
        vm.unregister_irqfd(&evtfd2, 8).unwrap();
        vm.unregister_irqfd(&evtfd3, 4).unwrap();
    }

    #[test]
    fn irqfd_resample() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd1 = EventFd::new().unwrap();
        let evtfd2 = EventFd::new().unwrap();
        vm.register_irqfd_resample(&evtfd1, &evtfd2, 4).unwrap();
        vm.unregister_irqfd(&evtfd1, 4).unwrap();
        // Ensures the ioctl is actually reading the resamplefd.
        vm.register_irqfd_resample(&evtfd1, unsafe { &EventFd::from_raw_fd(-1) }, 4)
            .unwrap_err();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_gsi_routing() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        vm.set_gsi_routing(&[]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: KVM_IRQCHIP_IOAPIC,
                pin: 3,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[
            IrqRoute {
                gsi: 1,
                source: IrqSource::Irqchip {
                    chip: KVM_IRQCHIP_IOAPIC,
                    pin: 3,
                },
            },
            IrqRoute {
                gsi: 2,
                source: IrqSource::Msi {
                    address: 0xf000000,
                    data: 0xa0,
                },
            },
        ])
        .unwrap();
    }

    #[test]
    fn create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        Vcpu::new(0, &kvm, &vm).unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn debugregs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        let mut dregs = vcpu.get_debugregs().unwrap();
        dregs.dr7 = 13;
        vcpu.set_debugregs(&dregs).unwrap();
        let dregs2 = vcpu.get_debugregs().unwrap();
        assert_eq!(dregs.dr7, dregs2.dr7);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn xcrs() {
        let kvm = Kvm::new().unwrap();
        if !kvm.check_extension(Cap::Xcrs) {
            return;
        }

        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        let mut xcrs = vcpu.get_xcrs().unwrap();
        xcrs.xcrs[0].value = 1;
        vcpu.set_xcrs(&xcrs).unwrap();
        let xcrs2 = vcpu.get_xcrs().unwrap();
        assert_eq!(xcrs.xcrs[0].value, xcrs2.xcrs[0].value);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        let mut msrs = vec![
            // This one should succeed
            kvm_msr_entry {
                index: 0x0000011e,
                ..Default::default()
            },
            // This one will fail to fetch
            kvm_msr_entry {
                index: 0x000003f1,
                ..Default::default()
            },
        ];
        vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(msrs.len(), 1);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn mp_state() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        let state = vcpu.get_mp_state().unwrap();
        vcpu.set_mp_state(&state).unwrap();
    }

    #[test]
    fn set_signal_mask() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        vcpu.set_signal_mask(&[sys_util::SIGRTMIN() + 0]).unwrap();
    }

    #[test]
    fn vcpu_mmap_size() {
        let kvm = Kvm::new().unwrap();
        let mmap_size = kvm.get_vcpu_mmap_size().unwrap();
        let page_size = pagesize();
        assert!(mmap_size >= page_size);
        assert!(mmap_size % page_size == 0);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_identity_map_addr() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.set_identity_map_addr(GuestAddress(0x20000)).unwrap();
    }
}
