// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages jailing and connecting virtio devices to the system bus.

use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use libc::{getresuid, getresgid, setresuid, setresgid, uid_t, gid_t, STDERR_FILENO};

use io_jail::Minijail;
use kvm::IoeventAddress;
use sys_util::{EventFd, GuestMemory, syslog};
use sys_util;

use hw;
use kernel_cmdline;
use vm_control::VmRequest;

/// Errors for device manager.
#[derive(Debug)]
pub enum Error {
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    /// Failed to clone a queue's ioeventfd.
    CloneIoeventFd(sys_util::Error),
    /// Failed to clone the mmio irqfd.
    CloneIrqFd(sys_util::Error),
    /// There was an error creating a sync EventFd.
    CreateSync(sys_util::Error),
    /// There was an error writing the uid_map.
    WriteUidMap(io::Error),
    /// There was an error writing the gid_map.
    WriteGidMap(io::Error),
    /// There was an error synchronizing the child process.
    Sync(sys_util::Error),
    /// Failed to initialize proxy device for jailed device.
    ProxyDeviceCreation(io::Error),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// No more IRQs are available.
    IrqsExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CreateMmioDevice(ref e) => write!(f, "failed to create mmio device: {:?}", e),
            &Error::CloneIoeventFd(ref e) => write!(f, "failed to clone ioeventfd: {:?}", e),
            &Error::CloneIrqFd(ref e) => write!(f, "failed to clone irqfd: {:?}", e),
            &Error::CreateSync(ref e) => write!(f, "failed to create sync eventfd: {:?}", e),
            &Error::WriteUidMap(ref e) => write!(f, "failed to write uid map: {}", e),
            &Error::WriteGidMap(ref e) => write!(f, "failed to write gid map: {}", e),
            &Error::Sync(ref e) => write!(f, "failed to sync proxy device start: {:?}", e),
            &Error::ProxyDeviceCreation(ref e) => write!(f, "failed to create proxy device: {}", e),
            &Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            &Error::IrqsExhausted => {
                write!(f, "no more IRQs are available")
            }
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

const MAX_IRQ: u32 = 15;

/// Manages the complexities of adding a device.
pub struct DeviceManager {
    pub bus: hw::Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemory,
    mmio_len: u64,
    mmio_base: u64,
    irq: u32,
}

impl DeviceManager {
    /// Create a new DeviceManager.
    pub fn new(guest_mem: GuestMemory, mmio_len: u64, mmio_base: u64, irq_base: u32) -> DeviceManager {
        DeviceManager {
            guest_mem: guest_mem,
            vm_requests: Vec::new(),
            mmio_len: mmio_len,
            mmio_base: mmio_base,
            irq: irq_base,
            bus: hw::Bus::new(),
        }
    }

    /// Register a device to be used via MMIO transport.
    pub fn register_mmio(&mut self,
                         device: Box<hw::virtio::VirtioDevice>,
                         jail: Option<Minijail>,
                         cmdline: &mut kernel_cmdline::Cmdline)
                         -> Result<()> {
        if self.irq > MAX_IRQ {
            return Err(Error::IrqsExhausted);
        }

        // List of FDs to keep open in the child after it forks.
        let mut keep_fds: Vec<RawFd> = device.keep_fds();
        keep_fds.push(STDERR_FILENO);
        syslog::push_fds(&mut keep_fds);

        let mmio_device = hw::virtio::MmioDevice::new(self.guest_mem.clone(), device)
            .map_err(Error::CreateMmioDevice)?;
        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoeventAddress::Mmio(self.mmio_base +
                                               hw::virtio::NOITFY_REG_OFFSET as u64);
            self.vm_requests.push(VmRequest::RegisterIoevent(queue_evt
                                                                 .try_clone()
                                                                 .map_err(Error::CloneIoeventFd)?,
                                                             io_addr,
                                                             i as u32));
            keep_fds.push(queue_evt.as_raw_fd());
        }

        if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
            self.vm_requests.push(VmRequest::RegisterIrqfd(interrupt_evt
                                                               .try_clone()
                                                               .map_err(Error::CloneIrqFd)?,
                                                           self.irq));
            keep_fds.push(interrupt_evt.as_raw_fd());
        }

        if let Some(jail) = jail {
            let (mut ruid, mut euid, mut suid) = (0, 0, 0);
            let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
            let mut id_map_done_evt = None;
            let needs_id_map = jail.get_uidmap().is_some() || jail.get_gidmap().is_some();
            if needs_id_map {
                id_map_done_evt = Some(EventFd::new().map_err(Error::CreateSync)?);
                // These never fail as long as they are given valid addresses, which are trivially
                // valid stack addresses.
                unsafe {
                    getresuid(&mut ruid as *mut uid_t,
                              &mut euid as *mut uid_t,
                              &mut suid as *mut uid_t);
                    getresgid(&mut rgid as *mut gid_t,
                              &mut egid as *mut gid_t,
                              &mut sgid as *mut gid_t);
                };
            };

            let proxy_dev = hw::ProxyDevice::new(mmio_device, |keep_pipe| {
                // The setresuid/setresgid calls will not work until the maps have been set, so we
                // wait for a signal indicating the uid/gid maps have been set by the parent.
                if let Some(evt) = id_map_done_evt.take() {
                    let _ = evt.read();
                    unsafe {
                        if jail.get_uidmap().is_some() {
                            setresuid(ruid, euid, suid);
                        }
                        if jail.get_gidmap().is_some() {
                            setresgid(rgid, egid, sgid);
                        }
                    }
                }
                keep_fds.push(keep_pipe.as_raw_fd());
                // Need to panic here as there isn't a way to recover from a
                // partly-jailed process.
                unsafe {
                    // This is OK as we have whitelisted all the FDs we need open.
                    // TODO(zachr): use jail.fork when that CL gets committed.
                    jail.enter(Some(&keep_fds)).unwrap();
                }
            }).map_err(|e| Error::ProxyDeviceCreation(e))?;

            if let Some(uid_map) = jail.get_uidmap() {
                let mut uid_file = fs::OpenOptions::new().write(true)
                        .read(false)
                        .create(false)
                        .open(format!("/proc/{}/uid_map", proxy_dev.pid()))
                        .unwrap();
                uid_file.write_all(uid_map.as_bytes()).map_err(Error::WriteUidMap)?;
            }

            if let Some(gid_map) = jail.get_gidmap() {
                let mut gid_file = fs::OpenOptions::new().write(true)
                        .read(false)
                        .create(false)
                        .open(format!("/proc/{}/gid_map", proxy_dev.pid()))
                        .unwrap();
                gid_file.write_all(gid_map.as_bytes()).map_err(Error::WriteGidMap)?;
            }

            // The proxy device process waits for this EventFd before setting its uid/gid, which
            // will only work after setting the above mappings.
            if let Some(evt) = id_map_done_evt {
                evt.write(1).map_err(Error::Sync)?;
            }

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
    use device_manager;
    use kernel_cmdline;
    use hw;

    const QUEUE_SIZES: &'static [u16] = &[64];

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl hw::virtio::VirtioDevice for DummyDevice {
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
                    queues: Vec<hw::virtio::Queue>,
                    mut queue_evts: Vec<EventFd>) {
        }
    }

    #[test]
    fn register_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)])
            .unwrap();
        let mut device_manager =
            device_manager::DeviceManager::new(guest_mem, 0x1000, 0xd0000000, 5);

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy_box = Box::new(DummyDevice { dummy: 0 });
        device_manager
            .register_mmio(dummy_box, None, &mut cmdline)
            .unwrap();
    }
}
