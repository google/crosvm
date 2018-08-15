// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module defines the protocol between `virtio-wayland` and `virtio-gpu` for sharing resources
//! that are backed by file descriptors.

use std::fs::File;
use std::io::Result;

use msg_on_socket_derive::MsgOnSocket;
use msg_socket::MsgSocket;

#[derive(MsgOnSocket)]
pub enum ResourceRequest {
    GetResource { id: u32 },
}

#[derive(MsgOnSocket)]
pub enum ResourceResponse {
    Resource(File),
    Invalid,
}

pub type ResourceRequestSocket = MsgSocket<ResourceRequest, ResourceResponse>;
pub type ResourceResponseSocket = MsgSocket<ResourceResponse, ResourceRequest>;

pub fn pair() -> Result<(ResourceRequestSocket, ResourceResponseSocket)> {
    msg_socket::pair()
}
