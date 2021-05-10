// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Errors that can happen while encoding or decoding.

use thiserror::Error as ThisError;

use crate::virtio::resource_bridge::ResourceBridgeError;
use crate::virtio::video::control::CtrlType;

/// An error indicating something went wrong while encoding or decoding.
/// Unlike `virtio::video::Error`, `VideoError` is not fatal for `Worker`.
#[derive(Debug, ThisError)]
pub enum VideoError {
    /// Invalid argument.
    #[error("invalid argument")]
    InvalidArgument,
    /// Invalid operation.
    #[error("invalid operation")]
    InvalidOperation,
    /// Invalid stream ID is specified.
    #[error("invalid stream ID {0}")]
    InvalidStreamId(u32),
    /// Invalid resource ID is specified.
    #[error("invalid resource ID {resource_id} for stream {stream_id}")]
    InvalidResourceId { stream_id: u32, resource_id: u32 },
    /// Invalid parameters are specified.
    #[error("invalid parameter")]
    InvalidParameter,
    /// No suitable format is supported.
    #[error("invalid format")]
    InvalidFormat,
    /// Failed to get a resource FD via resource_bridge.
    #[error("failed to get resource FD for id {0}")]
    ResourceBridgeFailure(ResourceBridgeError),
    /// Unsupported control type is specified.
    #[error("unsupported control: {0:?}")]
    UnsupportedControl(CtrlType),
    /// Backend-specific error.
    #[error("backend failure: {0}")]
    BackendFailure(Box<dyn std::error::Error + Send>),
}

pub type VideoResult<T> = Result<T, VideoError>;
