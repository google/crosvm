// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module defines the protocol between `virtio-wayland` and `virtio-gpu` for sharing resources
//! that are backed by file descriptors.

use std::fmt;
use std::fs::File;

use base::RawDescriptor;
use msg_on_socket_derive::MsgOnSocket;
use msg_socket::{MsgError, MsgReceiver, MsgSender, MsgSocket};

#[derive(MsgOnSocket)]
pub enum ResourceRequest {
    GetResource { id: u32 },
}

#[derive(MsgOnSocket, Clone)]
pub struct PlaneInfo {
    pub offset: u32,
    pub stride: u32,
}

const RESOURE_PLANE_NUM: usize = 4;
#[derive(MsgOnSocket)]
pub struct ResourceInfo {
    pub file: File,
    pub planes: [PlaneInfo; RESOURE_PLANE_NUM],
}

#[derive(MsgOnSocket)]
pub enum ResourceResponse {
    Resource(ResourceInfo),
    Invalid,
}

pub type ResourceRequestSocket = MsgSocket<ResourceRequest, ResourceResponse>;
pub type ResourceResponseSocket = MsgSocket<ResourceResponse, ResourceRequest>;

pub fn pair() -> std::io::Result<(ResourceRequestSocket, ResourceResponseSocket)> {
    msg_socket::pair()
}

#[derive(Debug)]
pub enum ResourceBridgeError {
    InvalidResource(u32),
    SendFailure(u32, MsgError),
    RecieveFailure(u32, MsgError),
}

impl fmt::Display for ResourceBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResourceBridgeError::InvalidResource(id) => {
                write!(f, "attempt to send non-existent gpu resource for id {}", id)
            }
            ResourceBridgeError::SendFailure(id, e) => write!(
                f,
                "failed to send a resource bridge request for id {}: {}",
                id, e
            ),
            ResourceBridgeError::RecieveFailure(id, e) => write!(
                f,
                "error receiving resource bridge response for id {}: {}",
                id, e
            ),
        }
    }
}

impl std::error::Error for ResourceBridgeError {}

pub fn get_resource_info(
    sock: &ResourceRequestSocket,
    id: u32,
) -> std::result::Result<ResourceInfo, ResourceBridgeError> {
    if let Err(e) = sock.send(&ResourceRequest::GetResource { id }) {
        return Err(ResourceBridgeError::SendFailure(id, e));
    }

    match sock.recv() {
        Ok(ResourceResponse::Resource(info)) => Ok(info),
        Ok(ResourceResponse::Invalid) => Err(ResourceBridgeError::InvalidResource(id)),
        Err(e) => Err(ResourceBridgeError::RecieveFailure(id, e)),
    }
}
