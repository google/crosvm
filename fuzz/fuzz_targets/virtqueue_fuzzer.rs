// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(test))]
#![no_main]

use std::io::Read;
use std::io::Write;
use std::mem::size_of;

use base::Event;
use crosvm_fuzz::fuzz_target;
use crosvm_fuzz::rand::FuzzRng;
use devices::virtio::Interrupt;
use devices::virtio::QueueConfig;
use devices::IrqLevelEvent;
use rand::Rng;
use rand::RngCore;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

const MAX_QUEUE_SIZE: u16 = 256;
const MEM_SIZE: u64 = 1024 * 1024;

thread_local! {
    static GUEST_MEM: GuestMemory = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
}

// These are taken from the virtio spec and can be used as a reference for the size calculations in
// the fuzzer.
#[repr(C, packed)]
struct virtq_desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct virtq_avail {
    flags: u16,
    idx: u16,
    ring: [u16; MAX_QUEUE_SIZE as usize],
    used_event: u16,
}

#[repr(C, packed)]
struct virtq_used_elem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
struct virtq_used {
    flags: u16,
    idx: u16,
    ring: [virtq_used_elem; MAX_QUEUE_SIZE as usize],
    avail_event: u16,
}

fuzz_target!(|data: &[u8]| {
    let interrupt = Interrupt::new(
        IrqLevelEvent::new().unwrap(),
        None,   // msix_config
        0xFFFF, // VIRTIO_MSI_NO_VECTOR
        #[cfg(target_arch = "x86_64")]
        None,
    );

    let mut q = QueueConfig::new(MAX_QUEUE_SIZE, 0);
    let mut rng = FuzzRng::new(data);
    q.set_size(rng.gen());

    // For each of {desc_table,avail_ring,used_ring} generate a random address that includes enough
    // space to hold the relevant struct with the largest possible queue size.
    let max_table_size = MAX_QUEUE_SIZE as u64 * size_of::<virtq_desc>() as u64;
    q.set_desc_table(GuestAddress(rng.gen_range(0..MEM_SIZE - max_table_size)));
    q.set_avail_ring(GuestAddress(
        rng.gen_range(0..MEM_SIZE - size_of::<virtq_avail>() as u64),
    ));
    q.set_used_ring(GuestAddress(
        rng.gen_range(0..MEM_SIZE - size_of::<virtq_used>() as u64),
    ));
    q.set_ready(true);

    GUEST_MEM.with(|mem| {
        let mut q = if let Ok(q) = q.activate(mem, Event::new().unwrap(), interrupt) {
            q
        } else {
            return;
        };

        // First zero out all of the memory.
        let vs = mem
            .get_slice_at_addr(GuestAddress(0), MEM_SIZE as usize)
            .unwrap();
        vs.write_bytes(0);

        // Fill in the descriptor table.
        let queue_size = q.size() as usize;
        let mut buf = vec![0u8; queue_size * size_of::<virtq_desc>()];

        rng.fill_bytes(&mut buf[..]);
        mem.write_all_at_addr(&buf[..], q.desc_table()).unwrap();

        // Fill in the available ring. See the definition of virtq_avail above for the source of
        // these numbers.
        let avail_size = 4 + (queue_size * 2) + 2;
        buf.resize(avail_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_all_at_addr(&buf[..], q.avail_ring()).unwrap();

        // Fill in the used ring. See the definition of virtq_used above for the source of
        // these numbers.
        let used_size = 4 + (queue_size * size_of::<virtq_used_elem>()) + 2;
        buf.resize(used_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_all_at_addr(&buf[..], q.used_ring()).unwrap();

        while let Some(mut avail_desc) = q.pop() {
            // Read the entire readable portion of the buffer.
            let mut read_buf = vec![0u8; avail_desc.reader.available_bytes()];
            avail_desc.reader.read_exact(&mut read_buf).unwrap();

            // Write the entire writable portion of the buffer.
            let write_buf = vec![0u8; avail_desc.writer.available_bytes()];
            avail_desc.writer.write_all(&write_buf).unwrap();

            q.add_used(avail_desc);
        }
    });
});
