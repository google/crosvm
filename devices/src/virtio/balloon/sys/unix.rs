// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use balloon_control::BalloonTubeResult;
use base::{error, warn, Tube};
use cros_async::{block_on, sync::Mutex as AsyncMutex, AsyncTube};
use vm_memory::{GuestAddress, GuestMemory};

use crate::virtio::balloon::virtio_balloon_config;
use crate::virtio::balloon::{BalloonState, VIRTIO_BALLOON_PFN_SHIFT};

// TODO nkgold (b/222588331): This relies on deref-ing an AsyncTube to a Tube. We should
// not allow AsyncTube to be deref'd to Tube and refactor this method.
pub(in crate::virtio::balloon) fn send_adjusted_response(
    tube: &Tube,
    num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    let num_bytes = (num_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;
    let result = BalloonTubeResult::Adjusted { num_bytes };
    tube.send(&result)
}

pub(in crate::virtio::balloon) async fn send_adjusted_response_async(
    tube: &AsyncTube,
    num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    let num_bytes = (num_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;
    let result = BalloonTubeResult::Adjusted { num_bytes };
    tube.send(result).await
}

pub(in crate::virtio::balloon) fn send_adjusted_response_if_needed(
    state: &Arc<AsyncMutex<BalloonState>>,
    command_tube: &Tube,
    config: virtio_balloon_config,
) {
    let mut state = block_on(state.lock());
    state.actual_pages = config.actual.to_native();
    if state.failable_update && state.actual_pages == state.num_pages {
        state.failable_update = false;
        if let Err(e) = send_adjusted_response(command_tube, state.num_pages) {
            error!("Failed to send response {:?}", e);
        }
    }
}

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
