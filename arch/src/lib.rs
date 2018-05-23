// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate sys_util;
extern crate resources;
extern crate kernel_cmdline;
extern crate kvm;
extern crate libc;
extern crate devices;

use std::ffi::CStr;
use std::fs::File;
use std::result;
use std::sync::{Arc, Mutex};

use devices::Bus;
use kvm::{Kvm, Vm, Vcpu};
use sys_util::{EventFd, GuestMemory};
use resources::SystemAllocator;

pub type Result<T> = result::Result<T, Box<std::error::Error>>;

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    fn load_kernel(mem: &GuestMemory, kernel_image: &mut File) -> Result<()>;

    /// Configures the system memory space should be called once per vm before
    /// starting vcpu threads.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest
    /// * `mem_size` - The size in bytes of system memory
    /// * `vcpu_count` - Number of virtual CPUs the guest will have
    /// * `cmdline` - the kernel commandline
    /// * `pci_irqs` - Any PCI irqs that need to be configured (Interrupt Line, PCI pin).
    fn setup_system_memory(mem: &GuestMemory,
                           mem_size: u64,
                           vcpu_count: u32,
                           cmdline: &CStr,
                           pci_irqs: Vec<(u32, devices::PciInterruptPin)>) -> Result<()>;

    /// Creates a new VM object and initializes architecture specific devices
    ///
    /// # Arguments
    ///
    /// * `kvm` - The opened /dev/kvm object.
    /// * `mem` - The memory to be used by the guest.
    fn create_vm(kvm: &Kvm, mem: GuestMemory) -> Result<Vm>;

    /// This adds any early platform devices for this architecture.
    ///
    /// # Arguments
    ///
    /// * `vm` - The vm to add irqs to.
    /// * `bus` - The bus to add devices to.
    fn add_arch_devs(_vm: &mut Vm, _bus: &mut Bus) -> Result<()> { Ok(()) }

    /// This creates a GuestMemory object for this VM
    ///
    /// * `mem_size` - Desired physical memory size in bytes for this VM
    fn setup_memory(mem_size: u64) -> Result<GuestMemory>;

    /// The creates the interrupt controller device and optionally returns the fd for it.
    /// Some architectures may not have a separate descriptor for the interrupt
    /// controller, so they would return None even on success.
    ///
    /// # Arguments
    ///
    /// * `vm` - the vm object
    fn create_irq_chip(vm: &kvm::Vm) -> Result<Option<File>>;

    /// This returns the first page frame number for use by the balloon driver.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - the size in bytes of physical ram for the guest
    fn get_base_dev_pfn(mem_size: u64) -> u64;

    /// This returns a minimal kernel command for this architecture.
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline;

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem_size: u64, gpu_allocation: bool) -> SystemAllocator;

    /// Sets up the IO bus for this platform
    ///
    /// # Arguments
    ///
    /// * - `vm` the vm object
    /// * - `exit_evt` - the event fd object which should receive exit events
    fn setup_io_bus(vm: &mut Vm, exit_evt: EventFd)
                    -> Result<(devices::Bus, Arc<Mutex<devices::Serial>>)>;

    /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The memory to be used by the guest.
    /// * `kernel_load_offset` - Offset in bytes from `guest_mem` at which the
    ///                          kernel starts.
    /// * `kvm` - The /dev/kvm object that created vcpu.
    /// * `vm` - The VM object associated with this VCPU.
    /// * `vcpu` - The VCPU object to configure.
    /// * `cpu_id` - The id of the given `vcpu`.
    /// * `num_cpus` - Number of virtual CPUs the guest will have.
    fn configure_vcpu(guest_mem: &GuestMemory,
                      kvm: &Kvm,
                      vm: &Vm,
                      vcpu: &Vcpu,
                      cpu_id: u64,
                      num_cpus: u64)
                      -> Result<()>;
}
