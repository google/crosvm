// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use cros_fuzz::fuzz_target;
use cros_fuzz::rand::FuzzRng;
use data_model::VolatileMemory;
use devices::virtio::Queue;
use rand::Rng;
use sys_util::{GuestAddress, GuestMemory};

const MAX_QUEUE_SIZE: u16 = 512;
const MEM_SIZE: u64 = 256 * 1024 * 1024;

thread_local! {
    static GUEST_MEM: GuestMemory = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
}

fuzz_target!(|data: &[u8]| {
    let mut q = Queue::new(MAX_QUEUE_SIZE);
    let mut rng = FuzzRng::new(data);
    q.max_size = rng.gen();
    q.size = rng.gen();
    q.ready = true;
    q.desc_table = GuestAddress(rng.gen_range(0, MEM_SIZE));
    q.avail_ring = GuestAddress(rng.gen_range(0, MEM_SIZE));
    q.used_ring = GuestAddress(rng.gen_range(0, MEM_SIZE));

    let back = rng.into_inner();
    GUEST_MEM.with(|mem| {
        // First zero out all of the memory.
        let vs = mem.get_slice(0, MEM_SIZE).unwrap();
        vs.write_bytes(0);

        // Then fill in the descriptor table.
        let mut off = mem.write_at_addr(back, q.desc_table).unwrap();

        // If there's any more data left, then fill in the available ring.
        if off < back.len() {
            off += mem.write_at_addr(&back[off..], q.avail_ring).unwrap();
        }

        // If there's still more put it in the used ring.
        if off < back.len() {
            mem.write_at_addr(&back[off..], q.used_ring).unwrap();
        }

        while let Some(desc_chain) = q.pop(mem) {
            let _ = desc_chain.into_iter().count();
        }
    });
});
