// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use balloon_control::BalloonTubeResult;
use base::Tube;

use crate::virtio::balloon::VIRTIO_BALLOON_PFN_SHIFT;

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
