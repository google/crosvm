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

#[derive(MsgOnSocket, Debug)]
pub enum ResourceRequest {
    GetBuffer { id: u32 },
    GetFence { seqno: u64 },
}

#[derive(MsgOnSocket, Clone, Copy, Default)]
pub struct PlaneInfo {
    pub offset: u32,
    pub stride: u32,
}

#[derive(MsgOnSocket)]
pub struct BufferInfo {
    pub file: File,
    pub planes: [PlaneInfo; RESOURE_PLANE_NUM],
}

pub const RESOURE_PLANE_NUM: usize = 4;
#[derive(MsgOnSocket)]
pub enum ResourceInfo {
    Buffer(BufferInfo),
    Fence { file: File },
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
    InvalidResource(ResourceRequest),
    SendFailure(ResourceRequest, MsgError),
    RecieveFailure(ResourceRequest, MsgError),
}

impl fmt::Display for ResourceRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResourceRequest::GetBuffer { id } => write!(f, "Buffer-{}", id),
            ResourceRequest::GetFence { seqno } => write!(f, "Fence-{}", seqno),
        }
    }
}

impl fmt::Display for ResourceBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResourceBridgeError::InvalidResource(req) => {
                write!(f, "attempt to send non-existent gpu resource for {}", req)
            }
            ResourceBridgeError::SendFailure(req, e) => write!(
                f,
                "failed to send a resource bridge request for {}: {}",
                req, e
            ),
            ResourceBridgeError::RecieveFailure(req, e) => write!(
                f,
                "error receiving resource bridge response for {}: {}",
                req, e
            ),
        }
    }
}

impl std::error::Error for ResourceBridgeError {}

pub fn get_resource_info(
    sock: &ResourceRequestSocket,
    request: ResourceRequest,
) -> std::result::Result<ResourceInfo, ResourceBridgeError> {
    if let Err(e) = sock.send(&request) {
        return Err(ResourceBridgeError::SendFailure(request, e));
    }

    match sock.recv() {
        Ok(ResourceResponse::Resource(info)) => Ok(info),
        Ok(ResourceResponse::Invalid) => Err(ResourceBridgeError::InvalidResource(request)),
        Err(e) => Err(ResourceBridgeError::RecieveFailure(request, e)),
    }
}
