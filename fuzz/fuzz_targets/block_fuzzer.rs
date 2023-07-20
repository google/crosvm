// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(test))]
#![no_main]

use std::collections::BTreeMap;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of;

use base::Event;
use crosvm_fuzz::fuzz_target;
use devices::virtio::base_features;
use devices::virtio::BlockAsync;
use devices::virtio::Interrupt;
use devices::virtio::QueueConfig;
use devices::virtio::VirtioDevice;
use devices::IrqLevelEvent;
use hypervisor::ProtectionType;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

const MEM_SIZE: u64 = 256 * 1024 * 1024;
const DESC_SIZE: u64 = 16; // Bytes in one virtio descriptor.
const QUEUE_SIZE: u16 = 16; // Max entries in the queue.
const CMD_SIZE: usize = 16; // Bytes in the command.

fuzz_target!(|bytes| {
    let size_u64 = size_of::<u64>();
    let mem = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();

    // The fuzz data is interpreted as:
    // starting index 8 bytes
    // command location 8 bytes
    // command 16 bytes
    // descriptors circular buffer 16 bytes * 3
    if bytes.len() < 4 * size_u64 {
        // Need an index to start.
        return;
    }

    let mut data_image = Cursor::new(bytes);

    let first_index = read_u64(&mut data_image);
    if first_index > MEM_SIZE / DESC_SIZE {
        return;
    }
    let first_offset = first_index * DESC_SIZE;
    if first_offset as usize + size_u64 > bytes.len() {
        return;
    }

    let command_addr = read_u64(&mut data_image);
    if command_addr > MEM_SIZE - CMD_SIZE as u64 {
        return;
    }
    if mem
        .write_all_at_addr(
            &bytes[2 * size_u64..(2 * size_u64) + CMD_SIZE],
            GuestAddress(command_addr),
        )
        .is_err()
    {
        return;
    }

    data_image.seek(SeekFrom::Start(first_offset)).unwrap();
    let desc_table = read_u64(&mut data_image);

    if mem
        .write_all_at_addr(&bytes[32..], GuestAddress(desc_table))
        .is_err()
    {
        return;
    }

    let mut q = QueueConfig::new(QUEUE_SIZE, 0);
    q.set_size(QUEUE_SIZE / 2);
    q.set_ready(true);
    let q = q.activate().expect("QueueConfig::activate");

    let queue_evt = Event::new().unwrap();

    let features = base_features(ProtectionType::Unprotected);

    let disk_file = tempfile::tempfile().unwrap();
    let mut block = BlockAsync::new(
        features,
        Box::new(disk_file),
        false,
        true,
        512,
        false,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    block
        .activate(
            mem,
            Interrupt::new(
                IrqLevelEvent::new().unwrap(),
                None,   // msix_config
                0xFFFF, // VIRTIO_MSI_NO_VECTOR
            ),
            BTreeMap::from([(0, (q, queue_evt.try_clone().unwrap()))]),
        )
        .unwrap();

    queue_evt.signal().unwrap(); // Rings the doorbell
});

fn read_u64<T: Read>(readable: &mut T) -> u64 {
    let mut buf = [0u8; size_of::<u64>()];
    readable.read_exact(&mut buf[..]).unwrap();
    u64::from_le_bytes(buf)
}
