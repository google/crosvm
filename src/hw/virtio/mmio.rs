// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use byteorder::{ByteOrder, LittleEndian};

use super::*;
use hw::BusDevice;
use sys_util::{Result, EventFd, GuestAddress, GuestMemory};

const VENDOR_ID: u32 = 0;

const MMIO_MAGIC_VALUE: u32 = 0x74726976;
const MMIO_VERSION: u32 = 2;

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_fds(&self) -> Vec<RawFd>;

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The set of feature bits shifted by `page * 32`.
    fn features(&self, page: u32) -> u32 {
        let _ = page;
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, page: u32, value: u32) {
        let _ = page;
        let _ = value;
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Activates this device for real usage.
    fn activate(&mut self,
                mem: GuestMemory,
                interrupt_evt: EventFd,
                status: Arc<AtomicUsize>,
                queues: Vec<Queue>,
                queue_evts: Vec<EventFd>);

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `hw::virtio::NOITFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioDevice {
    device: Box<VirtioDevice>,
    device_activated: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: Option<EventFd>,
    driver_status: u32,
    config_generation: u32,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    mem: Option<GuestMemory>,
}

impl MmioDevice {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(mem: GuestMemory, device: Box<VirtioDevice>) -> Result<MmioDevice> {
        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new()?)
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();
        Ok(MmioDevice {
               device: device,
               device_activated: false,
               features_select: 0,
               acked_features_select: 0,
               queue_select: 0,
               interrupt_status: Arc::new(AtomicUsize::new(0)),
               interrupt_evt: Some(EventFd::new()?),
               driver_status: 0,
               config_generation: 0,
               queues: queues,
               queue_evts: queue_evts,
               mem: Some(mem),
           })
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `hw::virtio::NOITFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    pub fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    /// Gets the event this device uses to interrupt the VM when the used queue is changed.
    pub fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
        self.driver_status == ready_bits && self.driver_status & DEVICE_FAILED == 0
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
        where F: FnOnce(&Queue) -> U
    {
        match self.queues.get(self.queue_select as usize) {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
            f(queue);
            true
        } else {
            false
        }
    }
}

impl BusDevice for MmioDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 4 {
            println!("invalid virtio mmio read of size {}", data.len());
            return;
        }

        let v = match offset {
            0x0 => MMIO_MAGIC_VALUE,
            0x004 => MMIO_VERSION,
            0x008 => self.device.device_type(),
            0x00c => VENDOR_ID, // vendor id
            0x010 => {
                self.device.features(self.features_select) |
                if self.features_select == 1 { 0x1 } else { 0x0 }
            }
            0x034 => self.with_queue(0, |q| q.max_size as u32),
            0x044 => self.with_queue(0, |q| q.ready as u32),
            0x060 => self.interrupt_status.load(Ordering::SeqCst) as u32,
            0x070 => self.driver_status,
            0x0fc => self.config_generation,
            o @ 0x100...0xfff if o % 4 == 0 => return self.device.read_config(offset - 0x100, data),
            _ => {
                println!("unknown virtio mmio read: 0x{:x}", offset);
                0
            }
        };

        LittleEndian::write_u32(data, v);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffffffff) | ((x as u64) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffffffff) | (x as u64)
        }

        if data.len() != 4 {
            println!("invalid virtio mmio write of size {}", data.len());
            return;
        }

        let mut mut_q = false;
        let v = LittleEndian::read_u32(data);
        match offset {
            0x014 => self.features_select = v,
            0x020 => self.device.ack_features(self.acked_features_select, v),
            0x024 => self.acked_features_select = v,
            0x030 => self.queue_select = v,
            0x038 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
            0x044 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
            0x050 => println!("received unexpected virtio queue notification via mmio write"),
            0x064 => {
                self.interrupt_status
                    .fetch_and(!(v as usize), Ordering::SeqCst);
            }
            0x070 => self.driver_status = v,
            0x080 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
            0x084 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
            0x090 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
            0x094 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
            0x0a0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
            0x0a4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
            o @ 0x100...0xfff if o % 4 == 0 => self.device.write_config(offset - 0x100, data),
            _ => {
                println!("unknown mmio write: 0x{:x} = {}", offset, v);
            }
        }

        if self.device_activated && mut_q {
            println!("warning: virtio queue was changed after device was activated");
        }

        if !self.device_activated && self.is_driver_ready() {
            if let Some(interrupt_evt) = self.interrupt_evt.take() {
                if let Some(mem) = self.mem.take() {
                    self.device
                        .activate(mem,
                                  interrupt_evt,
                                  self.interrupt_status.clone(),
                                  self.queues.clone(),
                                  self.queue_evts.split_off(0));
                    self.device_activated = true;
                }
            }
        }
    }
}
