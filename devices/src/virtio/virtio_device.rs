// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use sys_util::{EventFd, GuestMemory};

use super::*;
use crate::pci::{PciBarConfiguration, PciCapability};

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        match type_to_str(self.device_type()) {
            Some(s) => format!("virtio-{}", s),
            None => format!("virtio (type {})", self.device_type()),
        }
    }

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_fds(&self) -> Vec<RawFd>;

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The set of feature bits that this device supports.
    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) {
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
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    );

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }

    /// Returns any additional BAR configuration required by the device.
    fn get_device_bars(&self) -> Vec<PciBarConfiguration> {
        Vec::new()
    }

    /// Returns any additional capabiltiies required by the device.
    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        Vec::new()
    }
}
