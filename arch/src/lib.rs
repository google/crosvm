// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate io_jail;
extern crate sys_util;
extern crate resources;
extern crate kernel_cmdline;
extern crate kvm;
extern crate libc;
extern crate devices;

use std::fmt;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::{Arc, Mutex};

use devices::{Bus, PciDeviceList, Serial};
use devices::virtio::VirtioDevice;
use io_jail::Minijail;
use kvm::{IoeventAddress, Kvm, Vm, Vcpu};
use sys_util::{EventFd, GuestMemory, syslog};
use resources::SystemAllocator;

pub type Result<T> = result::Result<T, Box<std::error::Error>>;

/// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
/// create a `RunnableLinuxVm`.
pub struct VmComponents {
    pub pci_devices: PciDeviceList,
    pub memory_mb: u64,
    pub vcpu_count: u32,
    pub kernel_image: File,
    pub extra_kernel_params: Vec<String>,
    pub wayland_dmabuf: bool,
}

/// Holds the elements needed to run a Linux VM. Created by `build_vm`.
pub struct RunnableLinuxVm {
    pub vm: Vm,
    pub kvm: Kvm,
    pub resources: SystemAllocator,
    pub stdio_serial: Arc<Mutex<Serial>>,
    pub exit_evt: EventFd,
    pub vcpus: Vec<Vcpu>,
    pub irq_chip: Option<File>,
    pub io_bus: Bus,
    pub mmio_bus: Bus,
}

/// The device and optional jail.
pub struct VirtioDeviceStub {
    pub dev: Box<VirtioDevice>,
    pub jail: Option<Minijail>,
}

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    /// Takes `VmComponents` and generates a `RunnableLinuxVm`.
    ///
    /// # Arguments
    ///
    /// * `components` - Parts to use to build the VM.
    /// * `virtio_devs` - Function to generate a list of virtio devices.
    fn build_vm<F>(components: VmComponents, virtio_devs: F) -> Result<RunnableLinuxVm>
        where
            F: FnOnce(&GuestMemory, &EventFd) -> Result<Vec<VirtioDeviceStub>>;
}

/// Errors for device manager.
#[derive(Debug)]
pub enum MmioRegisterError {
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    /// Failed to register ioevent with VM.
    RegisterIoevent(sys_util::Error),
    /// Failed to register irq eventfd with VM.
    RegisterIrqfd(sys_util::Error),
    /// Failed to initialize proxy device for jailed device.
    ProxyDeviceCreation(devices::ProxyError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// No more MMIO space available.
    AddrsExhausted,
}

impl fmt::Display for MmioRegisterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &MmioRegisterError::CreateMmioDevice(ref e) => write!(f, "failed to create mmio device: {:?}", e),
            &MmioRegisterError::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            &MmioRegisterError::RegisterIoevent(ref e) => {
                write!(f, "failed to register ioevent to VM: {:?}", e)
            }
            &MmioRegisterError::RegisterIrqfd(ref e) => {
                write!(f, "failed to register irq eventfd to VM: {:?}", e)
            }
            &MmioRegisterError::ProxyDeviceCreation(ref e) => write!(f, "failed to create proxy device: {}", e),
            &MmioRegisterError::IrqsExhausted => write!(f, "no more IRQs are available"),
            &MmioRegisterError::AddrsExhausted => write!(f, "no more addresses are available"),
        }
    }
}

/// Register a device to be used via MMIO transport.
pub fn register_mmio(bus: &mut devices::Bus,
                     vm: &mut Vm,
                     device: Box<devices::virtio::VirtioDevice>,
                     jail: Option<Minijail>,
                     resources: &mut SystemAllocator,
                     cmdline: &mut kernel_cmdline::Cmdline)
                     -> std::result::Result<(), MmioRegisterError> {
    let irq = match resources.allocate_irq() {
        None => return Err(MmioRegisterError::IrqsExhausted),
        Some(i) => i,
    };

    // List of FDs to keep open in the child after it forks.
    let mut keep_fds: Vec<RawFd> = device.keep_fds();
    syslog::push_fds(&mut keep_fds);

    let mmio_device = devices::virtio::MmioDevice::new((*vm.get_memory()).clone(),
    device)
        .map_err(MmioRegisterError::CreateMmioDevice)?;
    let mmio_len = 0x1000; // TODO(dgreid) - configurable per arch?
    let mmio_base = resources.allocate_mmio_addresses(mmio_len)
        .ok_or(MmioRegisterError::AddrsExhausted)?;
    for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
        let io_addr = IoeventAddress::Mmio(mmio_base +
                                           devices::virtio::NOTIFY_REG_OFFSET as u64);
        vm.register_ioevent(&queue_evt, io_addr, i as u32)
          .map_err(MmioRegisterError::RegisterIoevent)?;
        keep_fds.push(queue_evt.as_raw_fd());
    }

    if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
        vm.register_irqfd(&interrupt_evt, irq)
          .map_err(MmioRegisterError::RegisterIrqfd)?;
        keep_fds.push(interrupt_evt.as_raw_fd());
    }

    if let Some(jail) = jail {
        let proxy_dev = devices::ProxyDevice::new(mmio_device, &jail, keep_fds)
            .map_err(MmioRegisterError::ProxyDeviceCreation)?;

        bus.insert(Arc::new(Mutex::new(proxy_dev)), mmio_base, mmio_len, false).unwrap();
    } else {
        bus.insert(Arc::new(Mutex::new(mmio_device)), mmio_base, mmio_len, false).unwrap();
    }

    cmdline
        .insert("virtio_mmio.device",
                &format!("4K@0x{:08x}:{}", mmio_base, irq))
        .map_err(MmioRegisterError::Cmdline)?;

    Ok(())
}
