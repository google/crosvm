// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module defines the protocol between `virtio-wayland` and `virtio-gpu` for sharing resources
//! that are backed by file descriptors.

use std::fmt;

use base::with_as_descriptor;
use base::SafeDescriptor;
use base::Tube;
use base::TubeError;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub enum ResourceRequest {
    GetBuffer { id: u32 },
    GetFence { seqno: u64 },
}

#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct PlaneInfo {
    pub offset: u32,
    pub stride: u32,
}

#[derive(Serialize, Deserialize)]
pub struct BufferInfo {
    #[serde(with = "with_as_descriptor")]
    pub handle: SafeDescriptor,
    pub planes: [PlaneInfo; RESOURE_PLANE_NUM],
    pub modifier: u64,
    /// Whether the buffer can be accessed by the guest CPU.
    pub guest_cpu_mappable: bool,
}

pub const RESOURE_PLANE_NUM: usize = 4;
#[derive(Serialize, Deserialize)]
pub enum ResourceInfo {
    Buffer(BufferInfo),
    Fence {
        #[serde(with = "with_as_descriptor")]
        handle: SafeDescriptor,
    },
}

#[derive(Serialize, Deserialize)]
pub enum ResourceResponse {
    Resource(ResourceInfo),
    Invalid,
}

#[sorted]
#[derive(Error, Debug)]
pub enum ResourceBridgeError {
    #[error("attempt to send non-existent gpu resource for {0}")]
    InvalidResource(ResourceRequest),
    #[error("error receiving resource bridge response for {0}: {1}")]
    RecieveFailure(ResourceRequest, TubeError),
    #[error("failed to send a resource bridge request for {0}: {1}")]
    SendFailure(ResourceRequest, TubeError),
}

impl fmt::Display for ResourceRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResourceRequest::GetBuffer { id } => write!(f, "Buffer-{}", id),
            ResourceRequest::GetFence { seqno } => write!(f, "Fence-{}", seqno),
        }
    }
}

pub fn get_resource_info(
    tube: &Tube,
    request: ResourceRequest,
) -> std::result::Result<ResourceInfo, ResourceBridgeError> {
    if let Err(e) = tube.send(&request) {
        return Err(ResourceBridgeError::SendFailure(request, e));
    }

    match tube.recv() {
        Ok(ResourceResponse::Resource(info)) => Ok(info),
        Ok(ResourceResponse::Invalid) => Err(ResourceBridgeError::InvalidResource(request)),
        Err(e) => Err(ResourceBridgeError::RecieveFailure(request, e)),
    }
}
