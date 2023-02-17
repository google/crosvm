// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::warn;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

pub(in crate::virtio::balloon) fn free_memory(
    guest_address: &GuestAddress,
    len: u64,
    mem: &GuestMemory,
) {
    if let Err(e) = mem.remove_range(*guest_address, len) {
        warn!("Marking pages unused failed: {}, addr={}", e, guest_address);
    }
}

// no-op
pub(in crate::virtio::balloon) fn reclaim_memory(_guest_address: &GuestAddress, _len: u64) {}
