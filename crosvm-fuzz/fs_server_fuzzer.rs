// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(test))]
#![no_main]

#[cfg(unix)]
mod fuzzer {
    use std::convert::TryInto;

    use cros_fuzz::fuzz_target;
    use devices::virtio::create_descriptor_chain;
    use devices::virtio::DescriptorType;
    use fuse::fuzzing::fuzz_server;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    const MEM_SIZE: u64 = 256 * 1024 * 1024;
    const BUFFER_ADDR: GuestAddress = GuestAddress(0x100);

    thread_local! {
        static GUEST_MEM: GuestMemory = GuestMemory::new(&[(GuestAddress(0), MEM_SIZE)]).unwrap();
    }

    fuzz_target!(|data| {
        use DescriptorType::*;

        GUEST_MEM.with(|mem| {
            mem.write_all_at_addr(data, BUFFER_ADDR).unwrap();

            // We need a valid descriptor chain, but it's not part of what is being fuzzed here.
            // So skip fuzzing if the chain is invalid.
            if let Ok(mut chain) = create_descriptor_chain(
                mem,
                GuestAddress(0),
                BUFFER_ADDR,
                vec![
                    (Readable, data.len().try_into().unwrap()),
                    (
                        Writable,
                        (MEM_SIZE as u32)
                            .saturating_sub(data.len().try_into().unwrap())
                            .saturating_sub(0x100),
                    ),
                ],
                0,
            ) {
                fuzz_server(&mut chain.reader, &mut chain.writer);
            }
        });
    });
}

#[cfg(not(unix))]
mod fuzzer {
    use cros_fuzz::fuzz_target;

    fuzz_target!(|_data| {});
}
