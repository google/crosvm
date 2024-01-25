// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::warn;
use vm_control::api::VmMemoryClient;
use vm_memory::GuestAddress;

pub(in crate::virtio::balloon) fn free_memory(
    guest_address: &GuestAddress,
    len: u64,
    vm_memory_client: &VmMemoryClient,
) {
    if let Err(e) = vm_memory_client.dynamically_free_memory_range(*guest_address, len) {
        warn!(
            "Failed to dynamically free memory range. Marking pages unused failed: {}, addr={}",
            e, guest_address
        );
    }
}

// no-op
pub(in crate::virtio::balloon) fn reclaim_memory(
    _guest_address: &GuestAddress,
    _len: u64,
    _vm_memory_client: &VmMemoryClient,
) {
}

// no-op
pub(in crate::virtio::balloon) fn balloon_target_reached(
    _size: u64,
    _vm_memory_client: &VmMemoryClient,
) {
}
