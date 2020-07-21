// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Errors that can happen while encoding or decoding.

use std::fmt;

use crate::virtio::resource_bridge::ResourceBridgeError;

/// An error indicating something went wrong while encoding or decoding.
/// Unlike `virtio::video::Error`, `VideoError` is not fatal for `Worker`.
#[derive(Debug)]
pub enum VideoError {
    /// Invalid argument.
    InvalidArgument,
    /// Invalid operation
    InvalidOperation,
    /// Invalid stream ID is specified.
    InvalidStreamId(u32),
    /// Invalid resource ID is specified.
    InvalidResourceId { stream_id: u32, resource_id: u32 },
    /// Invalid parameters are specified.
    InvalidParameter,
    /// Failed to get a resource FD via resource_bridge.
    ResourceBridgeFailure(ResourceBridgeError),
    /// `libvda` returned an error.
    VdaError(libvda::Error),
    /// `libvda` returned a failure response.
    VdaFailure(libvda::decode::Response),
}

impl fmt::Display for VideoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VideoError::*;
        match self {
            InvalidArgument => write!(f, "invalid argument"),
            InvalidOperation => write!(f, "invalid operation"),
            InvalidStreamId(id) => write!(f, "invalid stream ID {}", id),
            InvalidResourceId {
                stream_id,
                resource_id,
            } => write!(
                f,
                "invalid resource ID {} for stream {}",
                resource_id, stream_id
            ),
            InvalidParameter => write!(f, "invalid parameter"),
            ResourceBridgeFailure(id) => write!(f, "failed to get resource FD for id {}", id),
            VdaError(e) => write!(f, "error occurred in libvda: {}", e),
            VdaFailure(r) => write!(f, "failed while processing a requst in VDA: {}", r),
        }
    }
}

impl std::error::Error for VideoError {}

pub type VideoResult<T> = Result<T, VideoError>;
