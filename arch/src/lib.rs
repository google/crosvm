// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod android;
pub mod fdt;

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use devices::virtio::VirtioDevice;
use devices::{
    Bus, BusDevice, BusError, PciDevice, PciDeviceError, PciInterruptPin, PciRoot, ProxyDevice,
    Serial, SerialParameters, DEFAULT_SERIAL_PARAMS, SERIAL_ADDR,
};
use io_jail::Minijail;
use kvm::{IoeventAddress, Kvm, Vcpu, Vm};
use resources::SystemAllocator;
use sync::Mutex;
use sys_util::{syslog, EventFd, GuestAddress, GuestMemory, GuestMemoryError};

pub enum VmImage {
    Kernel(File),
    Bios(File),
}

/// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
/// create a `RunnableLinuxVm`.
pub struct VmComponents {
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub vcpu_affinity: Vec<usize>,
    pub vm_image: VmImage,
    pub android_fstab: Option<File>,
    pub initrd_image: Option<File>,
    pub extra_kernel_params: Vec<String>,
    pub wayland_dmabuf: bool,
}

/// Holds the elements needed to run a Linux VM. Created by `build_vm`.
pub struct RunnableLinuxVm {
    pub vm: Vm,
    pub kvm: Kvm,
    pub resources: SystemAllocator,
    pub stdio_serial: Option<Arc<Mutex<Serial>>>,
    pub exit_evt: EventFd,
    pub vcpus: Vec<Vcpu>,
    pub vcpu_affinity: Vec<usize>,
    pub irq_chip: Option<File>,
    pub io_bus: Bus,
    pub mmio_bus: Bus,
    pub pid_debug_label_map: BTreeMap<u32, String>,
}

/// The device and optional jail.
pub struct VirtioDeviceStub {
    pub dev: Box<dyn VirtioDevice>,
    pub jail: Option<Minijail>,
}

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    type Error: StdError;

    /// Takes `VmComponents` and generates a `RunnableLinuxVm`.
    ///
    /// # Arguments
    ///
    /// * `components` - Parts to use to build the VM.
    /// * `split_irqchip` - whether to use a split IRQ chip (i.e. userspace PIT/PIC/IOAPIC)
    /// * `serial_parameters` - definitions for how the serial devices should be configured.
    /// * `create_devices` - Function to generate a list of devices.
    fn build_vm<F, E>(
        components: VmComponents,
        split_irqchip: bool,
        serial_parameters: &BTreeMap<u8, SerialParameters>,
        create_devices: F,
    ) -> Result<RunnableLinuxVm, Self::Error>
    where
        F: FnOnce(
            &GuestMemory,
            &mut Vm,
            &mut SystemAllocator,
            &EventFd,
        ) -> Result<Vec<(Box<dyn PciDevice>, Option<Minijail>)>, E>,
        E: StdError + 'static;
}

/// Errors for device manager.
#[derive(Debug)]
pub enum DeviceRegistrationError {
    /// Could not allocate IO space for the device.
    AllocateIoAddrs(PciDeviceError),
    /// Could not allocate device address space for the device.
    AllocateDeviceAddrs(PciDeviceError),
    /// Could not allocate an IRQ number.
    AllocateIrq,
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    //  Unable to create serial device from serial parameters
    CreateSerialDevice(devices::SerialError),
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
    /// Could not register PCI device capabilities.
    RegisterDeviceCapabilities(PciDeviceError),
}

impl Display for DeviceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DeviceRegistrationError::*;

        match self {
            AllocateIoAddrs(e) => write!(f, "Allocating IO addresses: {}", e),
            AllocateDeviceAddrs(e) => write!(f, "Allocating device addresses: {}", e),
            AllocateIrq => write!(f, "Allocating IRQ number"),
            CreateMmioDevice(e) => write!(f, "failed to create mmio device: {}", e),
            CreateSerialDevice(e) => write!(f, "failed to create serial device: {}", e),
            Cmdline(e) => write!(f, "unable to add device to kernel command line: {}", e),
            EventFdCreate(e) => write!(f, "failed to create eventfd: {}", e),
            MmioInsert(e) => write!(f, "failed to add to mmio bus: {}", e),
            RegisterIoevent(e) => write!(f, "failed to register ioevent to VM: {}", e),
            RegisterIrqfd(e) => write!(f, "failed to register irq eventfd to VM: {}", e),
            ProxyDeviceCreation(e) => write!(f, "failed to create proxy device: {}", e),
            IrqsExhausted => write!(f, "no more IRQs are available"),
            AddrsExhausted => write!(f, "no more addresses are available"),
            RegisterDeviceCapabilities(e) => {
                write!(f, "could not register PCI device capabilities: {}", e)
            }
        }
    }
}

/// Creates a root PCI device for use by this Vm.
pub fn generate_pci_root(
    devices: Vec<(Box<dyn PciDevice>, Option<Minijail>)>,
    mmio_bus: &mut Bus,
    resources: &mut SystemAllocator,
    vm: &mut Vm,
) -> Result<(PciRoot, Vec<(u32, PciInterruptPin)>, BTreeMap<u32, String>), DeviceRegistrationError>
{
    let mut root = PciRoot::new();
    let mut pci_irqs = Vec::new();
    let mut pid_labels = BTreeMap::new();
    for (dev_idx, (mut device, jail)) in devices.into_iter().enumerate() {
        // Only support one bus.
        device.assign_bus_dev(0, dev_idx as u8);

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
        let device_ranges = device
            .allocate_device_bars(resources)
            .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;
        device
            .register_device_capabilities()
            .map_err(DeviceRegistrationError::RegisterDeviceCapabilities)?;
        for (event, addr, datamatch) in device.ioeventfds() {
            let io_addr = IoeventAddress::Mmio(addr);
            vm.register_ioevent(&event, io_addr, datamatch)
                .map_err(DeviceRegistrationError::RegisterIoevent)?;
            keep_fds.push(event.as_raw_fd());
        }
        let arced_dev: Arc<Mutex<dyn BusDevice>> = if let Some(jail) = jail {
            let proxy = ProxyDevice::new(device, &jail, keep_fds)
                .map_err(DeviceRegistrationError::ProxyDeviceCreation)?;
            pid_labels.insert(proxy.pid() as u32, proxy.debug_label());
            Arc::new(Mutex::new(proxy))
        } else {
            device.on_sandboxed();
            Arc::new(Mutex::new(device))
        };
        root.add_device(arced_dev.clone());
        for range in &ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }

        for range in &device_ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }
    Ok((root, pci_irqs, pid_labels))
}

/// Adds serial devices to the provided bus based on the serial parameters given. Returns the serial
///  port number and serial device to be used for stdout if defined.
///
/// # Arguments
///
/// * `io_bus` - Bus to add the devices to
/// * `com_evt_1_3` - eventfd for com1 and com3
/// * `com_evt_1_4` - eventfd for com2 and com4
/// * `io_bus` - Bus to add the devices to
/// * `serial_parameters` - definitions of serial parameter configuationis. If a setting is not
///     provided for a port, then it will use the default configuation.
pub fn add_serial_devices(
    io_bus: &mut Bus,
    com_evt_1_3: &EventFd,
    com_evt_2_4: &EventFd,
    serial_parameters: &BTreeMap<u8, SerialParameters>,
) -> Result<(Option<u8>, Option<Arc<Mutex<Serial>>>), DeviceRegistrationError> {
    let mut stdio_serial_num = None;
    let mut stdio_serial = None;

    for x in 0..=3 {
        let com_evt = match x {
            0 => com_evt_1_3,
            1 => com_evt_2_4,
            2 => com_evt_1_3,
            3 => com_evt_2_4,
            _ => com_evt_1_3,
        };

        let param = serial_parameters
            .get(&(x + 1))
            .unwrap_or(&DEFAULT_SERIAL_PARAMS[x as usize]);

        let com = Arc::new(Mutex::new(
            param
                .create_serial_device(&com_evt)
                .map_err(DeviceRegistrationError::CreateSerialDevice)?,
        ));
        io_bus
            .insert(com.clone(), SERIAL_ADDR[x as usize], 0x8, false)
            .unwrap();

        if param.console {
            stdio_serial_num = Some(x + 1);
            stdio_serial = Some(com.clone());
        }
    }

    Ok((stdio_serial_num, stdio_serial))
}

/// Errors for image loading.
#[derive(Debug)]
pub enum LoadImageError {
    BadAlignment(u64),
    Seek(io::Error),
    ImageSizeTooLarge(u64),
    ReadToMemory(GuestMemoryError),
}

impl Display for LoadImageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LoadImageError::*;

        match self {
            BadAlignment(a) => write!(f, "Alignment not a power of two: {}", a),
            Seek(e) => write!(f, "Seek failed: {}", e),
            ImageSizeTooLarge(size) => write!(f, "Image size too large: {}", size),
            ReadToMemory(e) => write!(f, "Reading image into memory failed: {}", e),
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
) -> Result<usize, LoadImageError>
where
    F: Read + Seek + AsRawFd,
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

/// Load an image from a file into guest memory at the highest possible address.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `image` - The file containing the image to be loaded.
/// * `min_guest_addr` - The minimum address of the start of the image.
/// * `max_guest_addr` - The address to load the last byte of the image.
/// * `align` - The minimum alignment of the start address of the image in bytes
///   (must be a power of two).
///
/// The guest address and size in bytes of the loaded image are returned.
pub fn load_image_high<F>(
    guest_mem: &GuestMemory,
    image: &mut F,
    min_guest_addr: GuestAddress,
    max_guest_addr: GuestAddress,
    align: u64,
) -> Result<(GuestAddress, usize), LoadImageError>
where
    F: Read + Seek + AsRawFd,
{
    if !align.is_power_of_two() {
        return Err(LoadImageError::BadAlignment(align));
    }

    let max_size = max_guest_addr.offset_from(min_guest_addr) & !(align - 1);
    let size = image.seek(SeekFrom::End(0)).map_err(LoadImageError::Seek)?;

    if size > usize::max_value() as u64 || size > max_size {
        return Err(LoadImageError::ImageSizeTooLarge(size));
    }

    image
        .seek(SeekFrom::Start(0))
        .map_err(LoadImageError::Seek)?;

    // Load image at the maximum aligned address allowed.
    // The subtraction cannot underflow because of the size checks above.
    let guest_addr = GuestAddress((max_guest_addr.offset() - size) & !(align - 1));

    // This is safe due to the bounds check above.
    let size = size as usize;

    guest_mem
        .read_to_memory(guest_addr, image, size)
        .map_err(LoadImageError::ReadToMemory)?;

    Ok((guest_addr, size))
}
