// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module defines the protocol between `virtio-wayland` and `virtio-gpu` for sharing resources
//! that are backed by file descriptors.

use std::fmt;
use std::fs::File;

use serde::{Deserialize, Serialize};

use base::{with_as_descriptor, Tube, TubeError};

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
    pub file: File,
    pub planes: [PlaneInfo; RESOURE_PLANE_NUM],
    pub modifier: u64,
}

pub const RESOURE_PLANE_NUM: usize = 4;
#[derive(Serialize, Deserialize)]
pub enum ResourceInfo {
    Buffer(BufferInfo),
    Fence {
        #[serde(with = "with_as_descriptor")]
        file: File,
    },
}

#[derive(Serialize, Deserialize)]
pub enum ResourceResponse {
    Resource(ResourceInfo),
    Invalid,
}

#[derive(Debug)]
pub enum ResourceBridgeError {
    InvalidResource(ResourceRequest),
    SendFailure(ResourceRequest, TubeError),
    RecieveFailure(ResourceRequest, TubeError),
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
