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
    use devices::virtio::Reader;
    use devices::virtio::Writer;
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

            let chain = create_descriptor_chain(
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
            )
            .unwrap();

            let r = Reader::new(&chain);
            let w = Writer::new(&chain);
            fuzz_server(r, w);
        });
    });
}

#[cfg(not(unix))]
mod fuzzer {
    use cros_fuzz::fuzz_target;

    fuzz_target!(|_data| {});
}
