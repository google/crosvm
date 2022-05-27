// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use balloon_control::BalloonTubeResult;
use base::{warn, Tube};
use cros_async::{AsyncMutex, AsyncTube};
use vm_control::{VmMemoryRequest, VmMemoryResponse};
use vm_memory::{GuestAddress, GuestMemory};

use crate::virtio::balloon::virtio_balloon_config;
use crate::virtio::balloon::{BalloonState, VIRTIO_BALLOON_PFN_SHIFT};

// TODO nkgold (b/222588331): Need AsyncTube to be able to be de-ref'd to Tube before this can be
// implemented.
pub(in crate::virtio::balloon) fn send_adjusted_response(
    _tube: &AsyncTube,
    _num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    Ok(())
}

pub(in crate::virtio::balloon) async fn send_adjusted_response_if_needed(
    state: &Arc<AsyncMutex<BalloonState>>,
    _command_tube: &Tube,
    config: virtio_balloon_config,
) {
    let mut state = block_on(self.state.lock());
    state.actual_pages = config.actual.to_native();
}

pub(in crate::virtio::balloon) async fn send_adjusted_response_async(
    tube: &AsyncTube,
    num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    let num_bytes = (num_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;
    let result = BalloonTubeResult::Adjusted { num_bytes };
    tube.send(result).await
}

pub(in crate::virtio::balloon) fn free_memory(
    guest_address: &GuestAddress,
    len: u64,
    dynamic_mapping_tube: &Tube,
) {
    let request = VmMemoryRequest::DynamicallyFreeMemoryRange { guest_address, len };
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

pub(in crate::virtio::balloon) fn reclaim_memory(guest_address: &GuestAddress, len: u64) {
    let request = VmMemoryRequest::DynamicallyReclaimMemoryRange { guest_address, len };
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
