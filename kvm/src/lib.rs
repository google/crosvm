// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.

extern crate libc;
extern crate kvm_sys;
extern crate sys_util;

mod cap;

use std::fs::File;
use std::mem;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{open, O_RDWR, EINVAL, ENOSPC};

use kvm_sys::*;

use sys_util::{GuestAddress, GuestMemory, MemoryMapping, EventFd, Error, Result};

pub use cap::*;

fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

unsafe fn ioctl<F: AsRawFd>(fd: &F, nr: c_ulong) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, 0)
}

unsafe fn ioctl_with_val<F: AsRawFd>(fd: &F, nr: c_ulong, arg: c_ulong) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, arg)
}

unsafe fn ioctl_with_ref<F: AsRawFd, T>(fd: &F, nr: c_ulong, arg: &T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, arg as *const T as *const c_void)
}

unsafe fn ioctl_with_mut_ref<F: AsRawFd, T>(fd: &F, nr: c_ulong, arg: &mut T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, arg as *mut T as *mut c_void)
}

unsafe fn ioctl_with_ptr<F: AsRawFd, T>(fd: &F, nr: c_ulong, arg: *const T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, arg as *const c_void)
}

unsafe fn ioctl_with_mut_ptr<F: AsRawFd, T>(fd: &F, nr: c_ulong, arg: *mut T) -> c_int {
    libc::ioctl(fd.as_raw_fd(), nr, arg as *mut c_void)
}

unsafe fn set_user_memory_region<F: AsRawFd>(fd: &F, slot: u32, guest_addr: u64, memory_size: u64, userspace_addr: u64) -> Result<()> {
    let region = kvm_userspace_memory_region {
        slot: slot,
        flags: 0,
        guest_phys_addr: guest_addr,
        memory_size: memory_size,
        userspace_addr: userspace_addr,
    };

    let ret = ioctl_with_ref(fd, KVM_SET_USER_MEMORY_REGION(), &region);
    if ret == 0 {
        Ok(())
    } else {
        errno_result()
    }
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
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, O_RDWR) };
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
                println!("warning: kernel returned invalid number of VCPUs");
                4
            },
        }
    }

    /// X86 specific call to get the system supported CPUID values
    ///
    /// # Arguments
    ///
    /// * `max_cpus` - Maximum number of cpuid entries to return.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self, max_cpus: usize) -> Result<CpuId> {
        let mut cpuid = CpuId::new(max_cpus);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(max_cpus) above.
            ioctl_with_mut_ptr(self, KVM_GET_SUPPORTED_CPUID(), cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return errno_result();
        }

        Ok(cpuid)
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

/// An address either in programmable I/O space or in memory mapped I/O space.
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

/// A wrapper around creating and using a VM.
pub struct Vm {
    vm: File,
    guest_mem: GuestMemory,
    next_mem_slot: usize,
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
                    set_user_memory_region(&vm_file, index as u32,
                        guest_addr.offset() as u64,
                        size as u64,
                        host_addr as u64)
                }
            })?;

            let next_mem_slot = guest_mem.num_regions();

            Ok(Vm {
                vm: vm_file,
                guest_mem: guest_mem,
                next_mem_slot: next_mem_slot,
            })
        } else {
            errno_result()
        }
    }

    /// Inserts the given `MemoryMapping` into the VM's address space at `guest_addr`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap
    /// with any other memory slot's region.
    pub fn add_device_memory(&mut self, guest_addr: GuestAddress, mem: MemoryMapping) -> Result<()> {
        if guest_addr < self.guest_mem.end_addr() {
            return Err(Error::new(ENOSPC));
        }

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this.
        unsafe {
            set_user_memory_region(&self.vm, self.next_mem_slot as u32,
                                        guest_addr.offset() as u64,
                                        mem.size() as u64,
                                        mem.as_ptr() as u64)?;
        };
        self.next_mem_slot += 1;

        Ok(())
    }

    /// Gets a reference to the memory at the given address in the VM's address space.
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
        *unsafe { irq_level.__bindgen_anon_1.irq.as_mut() } = irq;
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

    /// Registers an event to be signalled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit singalling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signalled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    pub fn register_ioevent<T: Into<u64>>(&self, evt: &EventFd, addr: IoeventAddress, datamatch: T) -> Result<()> {
        let mut flags = 0;
        if std::mem::size_of::<T>() > 0 {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        match addr {
            IoeventAddress::Pio(_) => flags |= 1 << kvm_ioeventfd_flag_nr_pio,
            _ => {}
        };
        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
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
                    let io = unsafe { run.__bindgen_anon_1.io.as_ref() };
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
                    let mmio = unsafe { run.__bindgen_anon_1.mmio.as_mut() };
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
}

impl AsRawFd for Vcpu {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

/// Wrapper for kvm_cpuid2 which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
pub struct CpuId {
    bytes: Vec<u8>, // Actually accessed as a kvm_cpuid2 struct.
    allocated_len: usize, // Number of kvm_cpuid_entry2 structs at the end of kvm_cpuid2.
}

impl CpuId {
    pub fn new(array_len: usize) -> CpuId {
        let vec_size_bytes = mem::size_of::<kvm_cpuid2>() +
            (array_len * mem::size_of::<kvm_cpuid_entry2>());
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
    fn add_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x1000), mem).unwrap();
    }

     #[test]
    fn overlap_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x2000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        assert!(vm.add_device_memory(GuestAddress(0x2000), mem).is_err());
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
    fn create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        Vcpu::new(0, &kvm, &vm).unwrap();
    }

    #[test]
    fn vcpu_mmap_size() {
        let kvm = Kvm::new().unwrap();
        let mmap_size = kvm.get_vcpu_mmap_size().unwrap();
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(mmap_size >= page_size);
        assert!(mmap_size % page_size == 0);
    }
}
