// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod fdt;

extern crate byteorder;
extern crate devices;
extern crate io_jail;
extern crate kernel_cmdline;
extern crate kvm;
extern crate libc;
extern crate resources;
extern crate sync;
extern crate sys_util;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;

use devices::virtio::VirtioDevice;
use devices::{
    Bus, BusDevice, BusError, PciDevice, PciDeviceError, PciInterruptPin, PciRoot, ProxyDevice,
    Serial,
};
use io_jail::Minijail;
use kvm::{IoeventAddress, Kvm, Vcpu, Vm};
use resources::SystemAllocator;
use sync::Mutex;
use sys_util::{syslog, EventFd, GuestAddress, GuestMemory, GuestMemoryError};

pub type Result<T> = result::Result<T, Box<std::error::Error>>;

/// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
/// create a `RunnableLinuxVm`.
pub struct VmComponents {
    pub memory_mb: u64,
    pub vcpu_count: u32,
    pub kernel_image: File,
    pub android_fstab: Option<File>,
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
    pub pid_debug_label_map: BTreeMap<u32, String>,
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
    /// * `split_irqchip` - whether to use a split IRQ chip (i.e. userspace PIT/PIC/IOAPIC)
    /// * `virtio_devs` - Function to generate a list of virtio devices.
    fn build_vm<F>(
        components: VmComponents,
        split_irqchip: bool,
        virtio_devs: F,
    ) -> Result<RunnableLinuxVm>
    where
        F: FnOnce(
            &GuestMemory,
            &EventFd,
        ) -> Result<Vec<(Box<PciDevice + 'static>, Option<Minijail>)>>;
}

/// Errors for device manager.
#[derive(Debug)]
pub enum DeviceRegistrationError {
    /// Could not allocate IO space for the device.
    AllocateIoAddrs(PciDeviceError),
    /// Could not allocate an IRQ number.
    AllocateIrq,
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    /// Could not create an event fd.
    EventFdCreate(sys_util::Error),
    /// Could not add a device to the mmio bus.
    MmioInsert(BusError),
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

impl fmt::Display for DeviceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeviceRegistrationError::AllocateIoAddrs(e) => {
                write!(f, "Allocating IO addresses: {:?}", e)
            }
            DeviceRegistrationError::AllocateIrq => write!(f, "Allocating IRQ number"),
            DeviceRegistrationError::CreateMmioDevice(e) => {
                write!(f, "failed to create mmio device: {:?}", e)
            }
            DeviceRegistrationError::Cmdline(e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            DeviceRegistrationError::EventFdCreate(e) => {
                write!(f, "failed to create eventfd: {:?}", e)
            }
            DeviceRegistrationError::MmioInsert(e) => {
                write!(f, "failed to add to mmio bus: {:?}", e)
            }
            DeviceRegistrationError::RegisterIoevent(e) => {
                write!(f, "failed to register ioevent to VM: {:?}", e)
            }
            DeviceRegistrationError::RegisterIrqfd(e) => {
                write!(f, "failed to register irq eventfd to VM: {:?}", e)
            }
            DeviceRegistrationError::ProxyDeviceCreation(e) => {
                write!(f, "failed to create proxy device: {}", e)
            }
            DeviceRegistrationError::IrqsExhausted => write!(f, "no more IRQs are available"),
            DeviceRegistrationError::AddrsExhausted => write!(f, "no more addresses are available"),
        }
    }
}

/// Creates a root PCI device for use by this Vm.
pub fn generate_pci_root(
    devices: Vec<(Box<PciDevice + 'static>, Option<Minijail>)>,
    mmio_bus: &mut Bus,
    resources: &mut SystemAllocator,
    vm: &mut Vm,
) -> std::result::Result<
    (PciRoot, Vec<(u32, PciInterruptPin)>, BTreeMap<u32, String>),
    DeviceRegistrationError,
> {
    let mut root = PciRoot::new();
    let mut pci_irqs = Vec::new();
    let mut pid_labels = BTreeMap::new();
    for (dev_idx, (mut device, jail)) in devices.into_iter().enumerate() {
        let mut keep_fds = device.keep_fds();
        syslog::push_fds(&mut keep_fds);

        let irqfd = EventFd::new().map_err(DeviceRegistrationError::EventFdCreate)?;
        let irq_resample_fd = EventFd::new().map_err(DeviceRegistrationError::EventFdCreate)?;
        let irq_num = resources
            .allocate_irq()
            .ok_or(DeviceRegistrationError::AllocateIrq)? as u32;
        let pci_irq_pin = match dev_idx % 4 {
            0 => PciInterruptPin::IntA,
            1 => PciInterruptPin::IntB,
            2 => PciInterruptPin::IntC,
            3 => PciInterruptPin::IntD,
            _ => panic!(""), // Obviously not possible, but the compiler is not smart enough.
        };
        vm.register_irqfd_resample(&irqfd, &irq_resample_fd, irq_num)
            .map_err(DeviceRegistrationError::RegisterIrqfd)?;
        keep_fds.push(irqfd.as_raw_fd());
        keep_fds.push(irq_resample_fd.as_raw_fd());
        device.assign_irq(irqfd, irq_resample_fd, irq_num, pci_irq_pin);
        pci_irqs.push((dev_idx as u32, pci_irq_pin));

        let ranges = device
            .allocate_io_bars(resources)
            .map_err(DeviceRegistrationError::AllocateIoAddrs)?;
        for (event, addr, datamatch) in device.ioeventfds() {
            let io_addr = IoeventAddress::Mmio(addr);
            vm.register_ioevent(&event, io_addr, datamatch)
                .map_err(DeviceRegistrationError::RegisterIoevent)?;
            keep_fds.push(event.as_raw_fd());
        }
        let arced_dev: Arc<Mutex<BusDevice>> = if let Some(jail) = jail {
            let proxy = ProxyDevice::new(device, &jail, keep_fds)
                .map_err(DeviceRegistrationError::ProxyDeviceCreation)?;
            pid_labels.insert(proxy.pid() as u32, proxy.debug_label());
            Arc::new(Mutex::new(proxy))
        } else {
            Arc::new(Mutex::new(device))
        };
        root.add_device(arced_dev.clone());
        for range in &ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }
    Ok((root, pci_irqs, pid_labels))
}

/// Errors for image loading.
#[derive(Debug)]
pub enum LoadImageError {
    Seek(std::io::Error),
    ImageSizeTooLarge(u64),
    ReadToMemory(GuestMemoryError),
}

impl fmt::Display for LoadImageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoadImageError::Seek(e) => write!(f, "Seek failed: {:?}", e),
            LoadImageError::ImageSizeTooLarge(size) => {
                write!(f, "Image size too large: {:?}", size)
            }
            LoadImageError::ReadToMemory(e) => {
                write!(f, "Reading image into memory failed: {:?}", e)
            }
        }
    }
}

/// Load an image from a file into guest memory.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `guest_addr` - The starting address to load the image in the guest memory.
/// * `max_size` - The amount of space in bytes available in the guest memory for the image.
/// * `image` - The file containing the image to be loaded.
///
/// The size in bytes of the loaded image is returned.
pub fn load_image<F>(
    guest_mem: &GuestMemory,
    image: &mut F,
    guest_addr: GuestAddress,
    max_size: u64,
) -> std::result::Result<usize, LoadImageError>
where
    F: Read + Seek,
{
    let size = image.seek(SeekFrom::End(0)).map_err(LoadImageError::Seek)?;

    if size > usize::max_value() as u64 || size > max_size {
        return Err(LoadImageError::ImageSizeTooLarge(size));
    }

    // This is safe due to the bounds check above.
    let size = size as usize;

    image
        .seek(SeekFrom::Start(0))
        .map_err(LoadImageError::Seek)?;

    guest_mem
        .read_to_memory(guest_addr, image, size)
        .map_err(LoadImageError::ReadToMemory)?;

    Ok(size)
}
