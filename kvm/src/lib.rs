// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.

extern crate libc;
extern crate kvm_sys;
#[macro_use]
extern crate sys_util;

mod cap;

use std::fs::File;
use std::collections::{BinaryHeap, HashMap};
use std::collections::hash_map::Entry;
use std::mem::size_of;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{open, O_RDWR, O_CLOEXEC, EINVAL, ENOSPC, ENOENT};
use libc::sigset_t;

use kvm_sys::*;

use sys_util::{GuestAddress, GuestMemory, MemoryMapping, EventFd,
               signal, Error, Result, pagesize};
#[allow(unused_imports)]
use sys_util::{ioctl, ioctl_with_val, ioctl_with_ref, ioctl_with_mut_ref, ioctl_with_ptr,
               ioctl_with_mut_ptr};

pub use cap::*;

const MAX_KVM_CPUID_ENTRIES: usize = 256;

fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

unsafe fn set_user_memory_region<F: AsRawFd>(fd: &F,
                                             slot: u32,
                                             read_only: bool,
                                             log_dirty_pages: bool,
                                             guest_addr: u64,
                                             memory_size: u64,
                                             userspace_addr: u64)
                                             -> Result<()> {
    let mut flags = if read_only {
        KVM_MEM_READONLY
    } else {
        0
    };
    if log_dirty_pages {
        flags |= KVM_MEM_LOG_DIRTY_PAGES;
    }
    let region = kvm_userspace_memory_region {
        slot: slot,
        flags,
        guest_phys_addr: guest_addr,
        memory_size: memory_size,
        userspace_addr: userspace_addr,
    };

    let ret = ioctl_with_ref(fd, KVM_SET_USER_MEMORY_REGION(), &region);
    if ret == 0 { Ok(()) } else { errno_result() }
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
            kvm: unsafe { File::from_raw_fd(ret) }
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
            },
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: u64) -> Result<CpuId> {
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
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone)]
pub enum IoeventAddress {
    Pio(u64),
    Mmio(u64),
}

/// Used in `Vm::register_ioevent` to indicate that no datamatch is requested.
pub struct NoDatamatch;
impl Into<u64> for NoDatamatch {
    fn into(self) -> u64 {
        0
    }
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

/// A wrapper around creating and using a VM.
pub struct Vm {
    vm: File,
    guest_mem: GuestMemory,
    device_memory: HashMap<u32, MemoryMapping>,
    mem_slot_gaps: BinaryHeap<i32>,
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
            guest_mem.with_regions(|index, guest_addr, size, host_addr| {
                unsafe {
                    // Safe because the guest regions are guaranteed not to overlap.
                    set_user_memory_region(&vm_file, index as u32, false, false,
                        guest_addr.offset() as u64,
                        size as u64,
                        host_addr as u64)
                }
            })?;

            Ok(Vm {
                vm: vm_file,
                guest_mem: guest_mem,
                device_memory: HashMap::new(),
                mem_slot_gaps: BinaryHeap::new(),
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
    pub fn add_device_memory(&mut self,
                             guest_addr: GuestAddress,
                             mem: MemoryMapping,
                             read_only: bool,
                             log_dirty_pages: bool)
                             -> Result<u32> {
        if guest_addr < self.guest_mem.end_addr() {
            return Err(Error::new(ENOSPC));
        }

        // The slot gaps are stored negated because `mem_slot_gaps` is a max-heap, so we negate the
        // popped value from the heap to get the lowest slot. If there are no gaps, the lowest slot
        // number is equal to the number of slots we are currently using between guest memory and
        // device memory. For example, if 2 slots are used by guest memory, 3 slots are used for
        // device memory, and there are no gaps, it follows that the lowest unused slot is 2+3=5.
        let slot = match self.mem_slot_gaps.pop() {
            Some(gap) => (-gap) as u32,
            None => (self.device_memory.len() + self.guest_mem.num_regions() as usize) as u32,
        };

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        unsafe {
            set_user_memory_region(&self.vm, slot, read_only, log_dirty_pages,
                                        guest_addr.offset() as u64,
                                        mem.size() as u64,
                                        mem.as_ptr() as u64)?;
        };
        self.device_memory.insert(slot, mem);

        Ok(slot)
    }

    /// Removes device memory that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_device_memory(&mut self, slot: u32) -> Result<MemoryMapping> {
        match self.device_memory.entry(slot) {
            Entry::Occupied(entry) => {
                // Safe because the slot is checked against the list of device memory slots.
                unsafe {
                    set_user_memory_region(&self.vm, slot, false, false, 0, 0, 0)?;
                }
                // Because `mem_slot_gaps` is a max-heap, but we want to pop the min slots, we
                // negate the slot value before insertion.
                self.mem_slot_gaps.push(-(slot as i32));
                Ok(entry.remove())
            }
            _ => Err(Error::new(ENOENT))
        }
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
                if ret == 0 { Ok(()) } else { errno_result() }
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
        let ret = unsafe {
            ioctl_with_val(self, KVM_SET_TSS_ADDR(), addr.offset() as u64)
        };
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
        let ret = unsafe {
            ioctl_with_ref(self, KVM_SET_IDENTITY_MAP_ADDR(), &(addr.offset() as u64))
        };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Crates an in kernel interrupt controller.
    ///
    /// See the documentation on the KVM_CREATE_IRQCHIP ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
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

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit signaling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signaled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    pub fn register_ioevent<T: Into<u64>>(&self, evt: &EventFd, addr: IoeventAddress, datamatch: T) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch.into(), std::mem::size_of::<T>() as u32, false)
    }

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    pub fn unregister_ioevent<T: Into<u64>>(&self, evt: &EventFd, addr: IoeventAddress, datamatch: T) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch.into(), std::mem::size_of::<T>() as u32, true)
    }

    fn ioeventfd(&self, evt: &EventFd, addr: IoeventAddress, datamatch: u64, datamatch_len: u32, deassign: bool) -> Result<()> {
        let mut flags = 0;
        if deassign {
            flags |= 1 << kvm_ioeventfd_flag_nr_deassign;
        }
        if datamatch_len > 0 {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        match addr {
            IoeventAddress::Pio(_) => flags |= 1 << kvm_ioeventfd_flag_nr_pio,
            _ => {}
        };
        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch,
            len: datamatch_len,
            addr: match addr { IoeventAddress::Pio(p) => p as u64, IoeventAddress::Mmio(m) => m },
            fd: evt.as_raw_fd(),
            flags: flags,
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    pub fn register_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_fd() as u32,
            gsi: gsi,
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    pub fn register_irqfd_resample(&self,
                                   evt: &EventFd,
                                   resample_evt: &EventFd,
                                   gsi: u32)
                                   -> Result<()> {
        let irqfd = kvm_irqfd {
            flags: KVM_IRQFD_FLAG_RESAMPLE,
            fd: evt.as_raw_fd() as u32,
            resamplefd: resample_evt.as_raw_fd() as u32,
            gsi: gsi,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 { Ok(()) } else { errno_result() }
    }

    /// Unregisters an event that was previously registered with
    /// `register_irqfd`/`register_irqfd_resample`.
    ///
    /// The `evt` and `gsi` pair must be the same as the ones passed into
    /// `register_irqfd`/`register_irqfd_resample`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"))]
    pub fn unregister_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_fd() as u32,
            gsi: gsi,
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
        let vec_size_bytes = size_of::<kvm_irq_routing>() +
            (routes.len() * size_of::<kvm_irq_routing_entry>());
        let bytes: Vec<u8> = vec![0; vec_size_bytes];
        let irq_routing: &mut kvm_irq_routing = unsafe {
            // We have ensured in new that there is enough space for the structure so this
            // conversion is safe.
            &mut *(bytes.as_ptr() as *mut kvm_irq_routing)
        };
        irq_routing.nr = routes.len() as u32;

        {
            // Safe because we ensured there is enough space in irq_routing to hold the number of
            // route entries.
            let irq_routes = unsafe { irq_routing.entries.as_mut_slice(routes.len()) };
            for (route, irq_route) in routes.iter().zip(irq_routes.iter_mut()) {
                irq_route.gsi = route.gsi;
                match route.source {
                    IrqSource::Irqchip { chip, pin } => {
                        irq_route.type_ = KVM_IRQ_ROUTING_IRQCHIP;
                        irq_route.u.irqchip = kvm_irq_routing_irqchip {
                            irqchip: chip,
                            pin,
                        }
                    }
                    IrqSource::Msi { address, data } => {
                        irq_route.type_ = KVM_IRQ_ROUTING_MSI;
                        irq_route.u.msi = kvm_irq_routing_msi {
                            address_lo: address as u32,
                            address_hi: (address >> 32) as u32,
                            data: data,
                            ..Default::default()
                        }
                    }
                }
            }
        }

        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GSI_ROUTING(), irq_routing) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl AsRawFd for Vm {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

/// A reason why a VCPU exited. One of these returns everytim `Vcpu::run` is called.
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before `Vcpu::run` is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before `Vcpu::run` is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
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
    SystemEvent,
}

/// A wrapper around creating and using a VCPU.
pub struct Vcpu {
    vcpu: File,
    run_mmap: MemoryMapping,
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
            return errno_result()
        }

        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let run_mmap = MemoryMapping::from_fd(&vcpu, run_mmap_size)
            .map_err(|_| Error::new(ENOSPC))?;

        Ok(Vcpu {
            vcpu: vcpu,
            run_mmap: run_mmap
        })
    }

    fn get_run(&self) -> &mut kvm_run {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        unsafe { &mut *(self.run_mmap.as_ptr() as *mut kvm_run) }
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            let run = self.get_run();
            match run.exit_reason {
                KVM_EXIT_IO => {
                    let run_start = run as *mut kvm_run as *mut u8;
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port =  io.port;
                    let data_size = io.count as usize * io.size as usize;
                    // The data_offset is defined by the kernel to be some number of bytes into the
                    // kvm_run stucture, which we have fully mmap'd.
                    let data_ptr = unsafe { run_start.offset(io.data_offset as isize) };
                    // The slice's lifetime is limited to the lifetime of this Vcpu, which is equal
                    // to the mmap of the kvm_run struct that this is slicing from
                    let data_slice = unsafe {
                        std::slice::from_raw_parts_mut::<u8>(data_ptr as *mut u8, data_size)
                    };
                    match io.direction as u32 {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn(port, data_slice)),
                        KVM_EXIT_IO_OUT => Ok(VcpuExit::IoOut(port, data_slice)),
                        _ => Err(Error::new(EINVAL)),
                    }
                },
                KVM_EXIT_MMIO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                    let addr = mmio.phys_addr;
                    let len = mmio.len as usize;
                    let data_slice = &mut mmio.data[..len];
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite(addr, data_slice))
                    } else {
                        Ok(VcpuExit::MmioRead(addr, data_slice))
                    }
                },
                KVM_EXIT_UNKNOWN         => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION       => Ok(VcpuExit::Exception),
                KVM_EXIT_HYPERCALL       => Ok(VcpuExit::Hypercall),
                KVM_EXIT_DEBUG           => Ok(VcpuExit::Debug),
                KVM_EXIT_HLT             => Ok(VcpuExit::Hlt),
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN        => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY      => Ok(VcpuExit::FailEntry),
                KVM_EXIT_INTR            => Ok(VcpuExit::Intr),
                KVM_EXIT_SET_TPR         => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS      => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC      => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET      => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR             => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI             => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR  => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI             => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL      => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL   => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG        => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH       => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR             => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT    => Ok(VcpuExit::SystemEvent),
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
            return errno_result()
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
            return errno_result()
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
            return errno_result()
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

    /// X86 specific call to get the MSRS
    ///
    /// See the documentation for KVM_SET_MSRS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msr_entries: &mut [kvm_msr_entry]) -> Result<()> {
        let vec_size_bytes = size_of::<kvm_msrs>() +
                             (msr_entries.len() * size_of::<kvm_msr_entry>());
        let vec: Vec<u8> = vec![0; vec_size_bytes];
        let msrs: &mut kvm_msrs = unsafe {
            // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
            // vector to size and set the members ensures no out-of-bounds errors below.
            &mut *(vec.as_ptr() as *mut kvm_msrs)
        };
        unsafe {
            // Mapping the unsized array to a slice is unsafe because the length isn't known.
            // Providing the length used to create the struct guarantees the entire slice is valid.
            let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(msr_entries.len());
            entries.copy_from_slice(&msr_entries);
        }
        msrs.nmsrs = msr_entries.len() as u32;
        let ret = unsafe {
            // Here we trust the kernel not to read or write past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_GET_MSRS(), msrs)
        };
        if ret < 0 {
            // KVM_SET_MSRS actually returns the number of msr entries written.
            return errno_result();
        }
        unsafe {
            let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(msr_entries.len());
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
        if ret < 0 { // KVM_SET_MSRS actually returns the number of msr entries written.
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

    /// Specifies set of signals that are blocked during execution of KVM_RUN.
    /// Signals that are not blocked will will cause KVM_RUN to return
    /// with -EINTR.
    ///
    /// See the documentation for KVM_SET_SIGNAL_MASK
    pub fn set_signal_mask(&self, signals: &[c_int]) -> Result<()> {
        let sigset = signal::create_sigset(signals)?;

        let vec_size_bytes = size_of::<kvm_signal_mask>() + size_of::<sigset_t>();
        let vec: Vec<u8> = vec![0; vec_size_bytes];
        let kvm_sigmask: &mut kvm_signal_mask = unsafe {
            // Converting the vector's memory to a struct is unsafe.
            // Carefully using the read-only vector to size and set the members
            // ensures no out-of-bounds errors below.
            &mut *(vec.as_ptr() as *mut kvm_signal_mask)
        };

        // Rust definition of sigset_t takes 128 bytes, but the kernel only
        // expects 8-bytes structure, so we can't write
        // kvm_sigmask.len  = size_of::<sigset_t>() as u32;
        kvm_sigmask.len = 8;
        // Ensure the length is not too big.
        const _ASSERT: usize = size_of::<sigset_t>() - 8 as usize;

        // Safe as we allocated exactly the needed space
        unsafe {
            std::ptr::copy(&sigset, kvm_sigmask.sigset.as_mut_ptr() as *mut sigset_t, 1);
        }

        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the
            // kvm_signal_mask structure.
            ioctl_with_ref(self, KVM_SET_SIGNAL_MASK(), kvm_sigmask)
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
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
    bytes: Vec<u8>, // Actually accessed as a kvm_cpuid2 struct.
    allocated_len: usize, // Number of kvm_cpuid_entry2 structs at the end of kvm_cpuid2.
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    pub fn new(array_len: usize) -> CpuId {
        use std::mem::size_of;

        let vec_size_bytes = size_of::<kvm_cpuid2>() +
            (array_len * size_of::<kvm_cpuid_entry2>());
        let bytes: Vec<u8> = vec![0; vec_size_bytes];
        let kvm_cpuid: &mut kvm_cpuid2 = unsafe {
            // We have ensured in new that there is enough space for the structure so this
            // conversion is safe.
            &mut *(bytes.as_ptr() as *mut kvm_cpuid2)
        };
        kvm_cpuid.nent = array_len as u32;

        CpuId { bytes: bytes, allocated_len: array_len }
    }

    /// Get the entries slice so they can be modified before passing to the VCPU.
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        unsafe {
            // We have ensured in new that there is enough space for the structure so this
            // conversion is safe.
            let kvm_cpuid: &mut kvm_cpuid2 = &mut *(self.bytes.as_ptr() as *mut kvm_cpuid2);

            // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
            // the length we originally allocated with eliminates the possibility of overflow.
            if kvm_cpuid.nent as usize > self.allocated_len {
                kvm_cpuid.nent = self.allocated_len as u32;
            }
            kvm_cpuid.entries.as_mut_slice(kvm_cpuid.nent as usize)
        }
    }

    /// Get a  pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        self.bytes.as_ptr() as *const kvm_cpuid2
    }

    /// Get a mutable pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        self.bytes.as_mut_ptr() as *mut kvm_cpuid2
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
    fn add_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x1000), mem, false, false).unwrap();
    }

    #[test]
    fn add_memory_ro() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x1000), mem, true, false).unwrap();
    }

    #[test]
    fn remove_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        let mem_ptr = mem.as_ptr();
        let slot = vm.add_device_memory(GuestAddress(0x1000), mem, false, false).unwrap();
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
        assert!(vm.add_device_memory(GuestAddress(0x2000), mem, false, false).is_err());
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
    fn register_ioevent() {
        assert_eq!(std::mem::size_of::<NoDatamatch>(), 0);

        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd = EventFd::new().unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), NoDatamatch).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), NoDatamatch).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xc1), 0x7fu8).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xc2), 0x1337u16).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xc4), 0xdeadbeefu32).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xc8), 0xdeadbeefdeadbeefu64).unwrap();
    }

    #[test]
    fn unregister_ioevent() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let evtfd = EventFd::new().unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), NoDatamatch).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), NoDatamatch).unwrap();
        vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1004), 0x7fu8).unwrap();
        vm.unregister_ioevent(&evtfd, IoeventAddress::Pio(0xf4), NoDatamatch).unwrap();
        vm.unregister_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), NoDatamatch).unwrap();
        vm.unregister_ioevent(&evtfd, IoeventAddress::Mmio(0x1004), 0x7fu8).unwrap();
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
        vm.register_irqfd_resample(&evtfd1, unsafe { &EventFd::from_raw_fd(-1) }, 4).unwrap_err();
    }

    #[test]
    fn set_gsi_routing() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.set_gsi_routing(&[]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: KVM_IRQCHIP_IOAPIC,
                pin: 3,
            },
        }]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        }]).unwrap();
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
        ]).unwrap();
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
    fn get_msrs() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
        vcpu.get_msrs(&mut [kvm_msr_entry {
                                index: 0x0000011e,
                                ..Default::default()
                            },
                            kvm_msr_entry {
                                index: 0x000003f1,
                                ..Default::default()
                            }])
            .unwrap();
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
    fn set_identity_map_addr() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        vm.set_identity_map_addr(GuestAddress(0x20000)).unwrap();
    }
}
