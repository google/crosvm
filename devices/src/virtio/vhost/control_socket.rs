// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use msg_socket::{MsgOnSocket, MsgSocket};
use sys_util::Error as SysError;

#[derive(MsgOnSocket, Debug)]
pub enum VhostDevRequest {
    /// Mask or unmask all the MSI entries for a Virtio Vhost device.
    MsixChanged,
    /// Mask or unmask a MSI entry for a Virtio Vhost device.
    MsixEntryChanged(usize),
}

#[derive(MsgOnSocket, Debug)]
pub enum VhostDevResponse {
    Ok,
    Err(SysError),
}

pub type VhostDevRequestSocket = MsgSocket<VhostDevRequest, VhostDevResponse>;
pub type VhostDevResponseSocket = MsgSocket<VhostDevResponse, VhostDevRequest>;

/// Create control socket pair. This pair is used to communicate with the
/// virtio device process.
/// Mainly between the virtio and activate thread.
pub fn create_control_sockets() -> (
    Option<VhostDevRequestSocket>,
    Option<VhostDevResponseSocket>,
) {
    match msg_socket::pair::<VhostDevRequest, VhostDevResponse>() {
        Ok((request, response)) => (Some(request), Some(response)),
        _ => (None, None),
    }
}
