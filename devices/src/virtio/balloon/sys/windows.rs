// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use cros_async::AsyncTube;

// TODO nkgold (b/222588331): Need AsyncTube to be able to be de-ref'd to Tube before this can be
// implemented.
pub(in crate::virtio::balloon) fn send_adjusted_response(
    _tube: &AsyncTube,
    _num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    Ok(())
}
