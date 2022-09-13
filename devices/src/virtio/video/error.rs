// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Errors that can happen while encoding or decoding.

use remain::sorted;
use thiserror::Error as ThisError;

use crate::virtio::video::control::CtrlType;

/// An error indicating something went wrong while encoding or decoding.
/// Unlike `virtio::video::Error`, `VideoError` is not fatal for `Worker`.
#[sorted]
#[derive(Debug, ThisError)]
pub enum VideoError {
    /// Backend-specific error.
    #[error("backend failure: {0:#}")]
    BackendFailure(anyhow::Error),
    /// Invalid argument.
    #[error("invalid argument")]
    InvalidArgument,
    /// No suitable format is supported.
    #[error("invalid format")]
    InvalidFormat,
    /// Invalid operation.
    #[error("invalid operation")]
    InvalidOperation,
    /// Invalid parameters are specified.
    #[error("invalid parameter")]
    InvalidParameter,
    /// Invalid resource ID is specified.
    #[error("invalid resource ID {resource_id} for stream {stream_id}")]
    InvalidResourceId { stream_id: u32, resource_id: u32 },
    /// Invalid stream ID is specified.
    #[error("invalid stream ID {0}")]
    InvalidStreamId(u32),
    /// Unsupported control type is specified.
    /// This is only used by the encoder for now, ignore warning if it is compiled out.
    #[allow(dead_code)]
    #[error("unsupported control: {0:?}")]
    UnsupportedControl(CtrlType),
}

pub type VideoResult<T> = Result<T, VideoError>;
