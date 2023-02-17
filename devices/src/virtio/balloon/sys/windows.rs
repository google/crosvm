// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::warn;
use base::Tube;
use vm_control::VmMemoryRequest;
use vm_control::VmMemoryResponse;
use vm_memory::GuestAddress;

pub(in crate::virtio::balloon) fn free_memory(
    guest_address: &GuestAddress,
    len: u64,
    dynamic_mapping_tube: &Tube,
) {
    let request = VmMemoryRequest::DynamicallyFreeMemoryRange {
        guest_address: *guest_address,
        size: len,
    };
    if let Err(e) = dynamic_mapping_tube.send(&request) {
        warn!(
            "Failed to send free memory request. Marking pages unused failed: {}, addr={}",
            e, guest_address
        );
        return;
    }
    if let Err(e) = dynamic_mapping_tube.recv::<VmMemoryResponse>() {
        warn!(
            "Failed to receive free memory response. Marking pages unused failed: {}, addr={}",
            e, guest_address
        );
    }
}

pub(in crate::virtio::balloon) fn reclaim_memory(
    guest_address: &GuestAddress,
    len: u64,
    dynamic_mapping_tube: &Tube,
) {
    let request = VmMemoryRequest::DynamicallyReclaimMemoryRange {
        guest_address: *guest_address,
        size: len,
    };
    if let Err(e) = dynamic_mapping_tube.send(&request) {
        warn!(
            "Failed to send reclaim memory request. Marking pages used failed: {}, addr={}",
            e, guest_address
        );
        return;
    }
    if let Err(e) = dynamic_mapping_tube.recv::<VmMemoryResponse>() {
        warn!(
            "Failed to receive reclaim memory request. Marking pages used failed: {}, addr={}",
            e, guest_address
        );
    }
}
