// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;

use base::warn;
use vm_memory::GuestAddress;

use super::*;

/// Contains the data for reading and writing the common configuration structure of a virtio PCI
/// device.
///
/// * Registers:
/// ** About the whole device.
/// le32 device_feature_select;     // read-write
/// le32 device_feature;            // read-only for driver
/// le32 driver_feature_select;     // read-write
/// le32 driver_feature;            // read-write
/// le16 msix_config;               // read-write
/// le16 num_queues;                // read-only for driver
/// u8 device_status;               // read-write (driver_status)
/// u8 config_generation;           // read-only for driver
/// ** About a specific virtqueue.
/// le16 queue_select;              // read-write
/// le16 queue_size;                // read-write, power of 2, or 0.
/// le16 queue_msix_vector;         // read-write
/// le16 queue_enable;              // read-write (Ready)
/// le16 queue_notify_off;          // read-only for driver
/// le64 queue_desc;                // read-write
/// le64 queue_avail;               // read-write
/// le64 queue_used;                // read-write
pub struct VirtioPciCommonConfig {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: u16,
}

impl VirtioPciCommonConfig {
    pub fn read(
        &mut self,
        offset: u64,
        data: &mut [u8],
        queues: &mut [Queue],
        device: &mut dyn VirtioDevice,
    ) {
        match data.len() {
            1 => {
                let v = self.read_common_config_byte(offset);
                data[0] = v;
            }
            2 => {
                let v = self.read_common_config_word(offset, queues);
                data.copy_from_slice(&v.to_le_bytes());
            }
            4 => {
                let v = self.read_common_config_dword(offset, device);
                data.copy_from_slice(&v.to_le_bytes());
            }
            8 => {
                let v = self.read_common_config_qword(offset);
                data.copy_from_slice(&v.to_le_bytes());
            }
            _ => (),
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        queues: &mut [Queue],
        device: &mut dyn VirtioDevice,
    ) {
        match data.len() {
            1 => self.write_common_config_byte(offset, data[0]),
            2 => self.write_common_config_word(
                offset,
                // This unwrap (and those below) cannot fail since data.len() is checked.
                u16::from_le_bytes(data.try_into().unwrap()),
                queues,
            ),
            4 => self.write_common_config_dword(
                offset,
                u32::from_le_bytes(data.try_into().unwrap()),
                queues,
                device,
            ),
            8 => self.write_common_config_qword(
                offset,
                u64::from_le_bytes(data.try_into().unwrap()),
                queues,
            ),
            _ => (),
        }
    }

    fn read_common_config_byte(&self, offset: u64) -> u8 {
        // The driver is only allowed to do aligned, properly sized access.
        match offset {
            0x14 => self.driver_status,
            0x15 => self.config_generation,
            _ => 0,
        }
    }

    fn write_common_config_byte(&mut self, offset: u64, value: u8) {
        match offset {
            0x14 => self.driver_status = value,
            _ => {
                warn!("invalid virtio config byt access: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_word(&self, offset: u64, queues: &[Queue]) -> u16 {
        match offset {
            0x10 => self.msix_config,
            0x12 => queues.len() as u16, // num_queues
            0x16 => self.queue_select,
            0x18 => self.with_queue(queues, |q| q.size()).unwrap_or(0),
            0x1a => self.with_queue(queues, |q| q.vector()).unwrap_or(0),
            0x1c => {
                if self.with_queue(queues, |q| q.ready()).unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            0x1e => self.queue_select, // notify_off
            _ => 0,
        }
    }

    fn write_common_config_word(&mut self, offset: u64, value: u16, queues: &mut [Queue]) {
        match offset {
            0x10 => self.msix_config = value,
            0x16 => self.queue_select = value,
            0x18 => self.with_queue_mut(queues, |q| q.set_size(value)),
            0x1a => self.with_queue_mut(queues, |q| q.set_vector(value)),
            0x1c => self.with_queue_mut(queues, |q| q.set_ready(value == 1)),
            _ => {
                warn!("invalid virtio register word write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_dword(&self, offset: u64, device: &dyn VirtioDevice) -> u32 {
        match offset {
            0x00 => self.device_feature_select,
            0x04 => {
                // Only 64 bits of features (2 pages) are defined for now, so limit
                // device_feature_select to avoid shifting by 64 or more bits.
                if self.device_feature_select < 2 {
                    (device.features() >> (self.device_feature_select * 32)) as u32
                } else {
                    0
                }
            }
            0x08 => self.driver_feature_select,
            _ => 0,
        }
    }

    fn write_common_config_dword(
        &mut self,
        offset: u64,
        value: u32,
        queues: &mut [Queue],
        device: &mut dyn VirtioDevice,
    ) {
        macro_rules! hi {
            ($q:expr, $get:ident, $set:ident, $x:expr) => {
                $q.$set(($q.$get() & 0xffffffff) | (($x as u64) << 32))
            };
        }
        macro_rules! lo {
            ($q:expr, $get:ident, $set:ident, $x:expr) => {
                $q.$set(($q.$get() & !0xffffffff) | ($x as u64))
            };
        }

        match offset {
            0x00 => self.device_feature_select = value,
            0x08 => self.driver_feature_select = value,
            0x0c => {
                if self.driver_feature_select < 2 {
                    let features: u64 = (value as u64) << (self.driver_feature_select * 32);
                    device.ack_features(features);
                    for queue in queues.iter_mut() {
                        queue.ack_features(features);
                    }
                } else {
                    warn!(
                        "invalid ack_features (page {}, value 0x{:x})",
                        self.driver_feature_select, value
                    );
                }
            }
            0x20 => self.with_queue_mut(queues, |q| lo!(q, desc_table, set_desc_table, value)),
            0x24 => self.with_queue_mut(queues, |q| hi!(q, desc_table, set_desc_table, value)),
            0x28 => self.with_queue_mut(queues, |q| lo!(q, avail_ring, set_avail_ring, value)),
            0x2c => self.with_queue_mut(queues, |q| hi!(q, avail_ring, set_avail_ring, value)),
            0x30 => self.with_queue_mut(queues, |q| lo!(q, used_ring, set_used_ring, value)),
            0x34 => self.with_queue_mut(queues, |q| hi!(q, used_ring, set_used_ring, value)),
            _ => {
                warn!("invalid virtio register dword write: 0x{:x}", offset);
            }
        }
    }

    fn read_common_config_qword(&self, _offset: u64) -> u64 {
        0 // Assume the guest has no reason to read write-only registers.
    }

    fn write_common_config_qword(&mut self, offset: u64, value: u64, queues: &mut [Queue]) {
        match offset {
            0x20 => self.with_queue_mut(queues, |q| q.set_desc_table(GuestAddress(value))),
            0x28 => self.with_queue_mut(queues, |q| q.set_avail_ring(GuestAddress(value))),
            0x30 => self.with_queue_mut(queues, |q| q.set_used_ring(GuestAddress(value))),
            _ => {
                warn!("invalid virtio register qword write: 0x{:x}", offset);
            }
        }
    }

    fn with_queue<U, F>(&self, queues: &[Queue], f: F) -> Option<U>
    where
        F: FnOnce(&Queue) -> U,
    {
        queues.get(self.queue_select as usize).map(f)
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&self, queues: &mut [Queue], f: F) {
        if let Some(queue) = queues.get_mut(self.queue_select as usize) {
            f(queue);
        }
    }
}

#[cfg(test)]
mod tests {
    use base::Event;
    use base::RawDescriptor;
    use vm_memory::GuestMemory;

    use super::*;
    use crate::Suspendable;

    struct DummyDevice(DeviceType);
    const QUEUE_SIZE: u16 = 256;
    const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];
    const DUMMY_FEATURES: u64 = 0x5555_aaaa;
    impl VirtioDevice for DummyDevice {
        fn keep_rds(&self) -> Vec<RawDescriptor> {
            Vec::new()
        }
        fn device_type(&self) -> DeviceType {
            self.0
        }
        fn queue_max_sizes(&self) -> &[u16] {
            QUEUE_SIZES
        }
        fn activate(
            &mut self,
            _mem: GuestMemory,
            _interrupt: Interrupt,
            _queues: Vec<Queue>,
            _queue_evts: Vec<Event>,
        ) {
        }
        fn features(&self) -> u64 {
            DUMMY_FEATURES
        }
    }

    impl Suspendable for DummyDevice {}

    #[test]
    fn write_base_regs() {
        let mut regs = VirtioPciCommonConfig {
            driver_status: 0xaa,
            config_generation: 0x55,
            device_feature_select: 0x0,
            driver_feature_select: 0x0,
            queue_select: 0xff,
            msix_config: 0x00,
        };

        let dev = &mut DummyDevice(DeviceType::Rng) as &mut dyn VirtioDevice;
        let mut queues = Vec::new();

        // Can set all bits of driver_status.
        regs.write(0x14, &[0x55], &mut queues, dev);
        let mut read_back = vec![0x00];
        regs.read(0x14, &mut read_back, &mut queues, dev);
        assert_eq!(read_back[0], 0x55);

        // The config generation register is read only.
        regs.write(0x15, &[0xaa], &mut queues, dev);
        let mut read_back = vec![0x00];
        regs.read(0x15, &mut read_back, &mut queues, dev);
        assert_eq!(read_back[0], 0x55);

        // Device features is read-only and passed through from the device.
        regs.write(0x04, &[0, 0, 0, 0], &mut queues, dev);
        let mut read_back = [0u8; 4];
        regs.read(0x04, &mut read_back, &mut queues, dev);
        assert_eq!(u32::from_le_bytes(read_back), DUMMY_FEATURES as u32);

        // Feature select registers are read/write.
        regs.write(0x00, &[1, 2, 3, 4], &mut queues, dev);
        let mut read_back = [0u8; 4];
        regs.read(0x00, &mut read_back, &mut queues, dev);
        assert_eq!(u32::from_le_bytes(read_back), 0x0403_0201);
        regs.write(0x08, &[1, 2, 3, 4], &mut queues, dev);
        let mut read_back = [0u8; 4];
        regs.read(0x08, &mut read_back, &mut queues, dev);
        assert_eq!(u32::from_le_bytes(read_back), 0x0403_0201);

        // 'queue_select' can be read and written.
        regs.write(0x16, &[0xaa, 0x55], &mut queues, dev);
        let mut read_back = vec![0x00, 0x00];
        regs.read(0x16, &mut read_back, &mut queues, dev);
        assert_eq!(read_back[0], 0xaa);
        assert_eq!(read_back[1], 0x55);
    }
}
