// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages jailing and connecting virtio devices to the system bus.

extern crate devices;
extern crate io_jail;
extern crate kvm;
extern crate sys_util;
extern crate kernel_cmdline;

use std::fmt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use io_jail::Minijail;
use kvm::{Vm, IoeventAddress};
use sys_util::{GuestMemory, syslog};

/// Errors for device manager.
#[derive(Debug)]
pub enum Error {
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CreateMmioDevice(ref e) => write!(f, "failed to create mmio device: {:?}", e),
            &Error::RegisterIoevent(ref e) => {
                write!(f, "failed to register ioevent to VM: {:?}", e)
            }
            &Error::RegisterIrqfd(ref e) => {
                write!(f, "failed to register irq eventfd to VM: {:?}", e)
            }
            &Error::ProxyDeviceCreation(ref e) => write!(f, "failed to create proxy device: {}", e),
            &Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            &Error::IrqsExhausted => write!(f, "no more IRQs are available"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

const MAX_IRQ: u32 = 15;

/// Manages the complexities of adding a device.
pub struct DeviceManager<'a> {
    pub bus: devices::Bus,
    vm: &'a mut Vm,
    guest_mem: GuestMemory,
    mmio_len: u64,
    mmio_base: u64,
    irq: u32,
}

impl<'a> DeviceManager<'a> {
    /// Create a new DeviceManager.
    pub fn new(vm: &mut Vm,
               guest_mem: GuestMemory,
               mmio_len: u64,
               mmio_base: u64,
               irq_base: u32)
               -> DeviceManager {
        DeviceManager {
            bus: devices::Bus::new(),
            vm,
            guest_mem,
            mmio_len,
            mmio_base,
            irq: irq_base,
        }
    }

    /// Register a device to be used via MMIO transport.
    pub fn register_mmio(&mut self,
                         device: Box<devices::virtio::VirtioDevice>,
                         jail: Option<Minijail>,
                         cmdline: &mut kernel_cmdline::Cmdline)
                         -> Result<()> {
        if self.irq > MAX_IRQ {
            return Err(Error::IrqsExhausted);
        }

        // List of FDs to keep open in the child after it forks.
        let mut keep_fds: Vec<RawFd> = device.keep_fds();
        syslog::push_fds(&mut keep_fds);

        let mmio_device = devices::virtio::MmioDevice::new(self.guest_mem.clone(), device)
            .map_err(Error::CreateMmioDevice)?;
        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoeventAddress::Mmio(self.mmio_base +
                                               devices::virtio::NOITFY_REG_OFFSET as u64);
            self.vm
                .register_ioevent(&queue_evt, io_addr, i as u32)
                .map_err(Error::RegisterIoevent)?;
            keep_fds.push(queue_evt.as_raw_fd());
        }

        if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
            self.vm
                .register_irqfd(&interrupt_evt, self.irq)
                .map_err(Error::RegisterIrqfd)?;
            keep_fds.push(interrupt_evt.as_raw_fd());
        }

        if let Some(jail) = jail {
            let proxy_dev = devices::ProxyDevice::new(mmio_device, &jail, keep_fds)
                .map_err(Error::ProxyDeviceCreation)?;

            self.bus
                .insert(Arc::new(Mutex::new(proxy_dev)),
                        self.mmio_base,
                        self.mmio_len)
                .unwrap();
        } else {
            self.bus
                .insert(Arc::new(Mutex::new(mmio_device)),
                        self.mmio_base,
                        self.mmio_len)
                .unwrap();
        }

        cmdline
            .insert("virtio_mmio.device",
                    &format!("4K@0x{:08x}:{}", self.mmio_base, self.irq))
            .map_err(Error::Cmdline)?;
        self.mmio_base += self.mmio_len;
        self.irq += 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::os::unix::io::RawFd;
    use sys_util::{EventFd, GuestAddress, GuestMemory};
    use kvm::*;
    use DeviceManager;
    use kernel_cmdline;
    use devices;

    const QUEUE_SIZES: &'static [u16] = &[64];

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn keep_fds(&self) -> Vec<RawFd> {
            Vec::new()
        }

        fn device_type(&self) -> u32 {
            0
        }

        fn queue_max_sizes(&self) -> &[u16] {
            QUEUE_SIZES
        }

        #[allow(unused_variables)]
        #[allow(unused_mut)]
        fn activate(&mut self,
                    mem: GuestMemory,
                    interrupt_evt: EventFd,
                    status: Arc<AtomicUsize>,
                    queues: Vec<devices::virtio::Queue>,
                    mut queue_evts: Vec<EventFd>) {
        }
    }

    #[test]
    #[ignore] // no access to /dev/kvm
    fn register_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)])
            .unwrap();
        let mut vm = Vm::new(&Kvm::new().unwrap(), guest_mem.clone()).unwrap();
        let mut device_manager =
            DeviceManager::new(&mut vm, guest_mem, 0x1000, 0xd0000000, 5);

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy_box = Box::new(DummyDevice { dummy: 0 });
        device_manager
            .register_mmio(dummy_box, None, &mut cmdline)
            .unwrap();
    }
}
