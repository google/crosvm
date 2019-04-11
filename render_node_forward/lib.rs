// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::{GuestAddress, GuestMemory, MemoryMapping};

#[link(name = "rendernodehost")]
extern "C" {
    fn start_render_node_host(
        gpu_host_mem: *mut u8,
        gpu_guest_mem_start: u64,
        gpu_guest_mem_size: u64,
        host_start: *const u8,
        host_4g_start: *const u8,
    );
}

/// The number of bytes in 4 GiB.
pub const FOUR_GB: u64 = (1 << 32);
/// The size required for the render node host in host and guest address space.
pub const RENDER_NODE_HOST_SIZE: u64 = FOUR_GB;

/// A render node host device that interfaces with the guest render node forwarder.
pub struct RenderNodeHost {
    #[allow(dead_code)]
    guest_mem: GuestMemory,
}

impl RenderNodeHost {
    /// Starts the render node host forwarding service over the given guest and host address ranges.
    pub fn start(
        mmap: &MemoryMapping,
        gpu_guest_address: u64,
        guest_mem: GuestMemory,
    ) -> RenderNodeHost {
        // Render node forward library need to do address translation between host user space
        // address and guest physical address. We could call Rust function from C library. But
        // since it's actually a linear mapping now, we just pass the host start address to
        // render node forward library. We need two start address here since there would be a
        // hole below 4G if guest memory size is bigger than 4G.

        let host_start_addr = guest_mem.get_host_address(GuestAddress(0)).unwrap();
        let host_4g_addr = if guest_mem.memory_size() > FOUR_GB {
            guest_mem.get_host_address(GuestAddress(FOUR_GB)).unwrap()
        } else {
            host_start_addr
        };
        // Safe because only valid addresses are given.
        unsafe {
            start_render_node_host(
                mmap.as_ptr(),
                gpu_guest_address,
                mmap.size() as u64,
                host_start_addr,
                host_4g_addr,
            )
        }
        RenderNodeHost { guest_mem }
    }
}
