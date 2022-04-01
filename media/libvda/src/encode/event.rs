// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Events reported by VDA encode API over pipe FD.

use enumn::N;
use std::error;
use std::fmt::{self, Display};

use super::bindings;
use super::session::{VeaInputBufferId, VeaOutputBufferId};
use crate::error::*;

/// Represents an error from a libvda encode session.
#[derive(Debug, Clone, Copy, N)]
#[repr(u32)]
pub enum VeaError {
    IllegalState = bindings::vea_error_ILLEGAL_STATE_ERROR,
    InvalidArgument = bindings::vea_error_INVALID_ARGUMENT_ERROR,
    PlatformFailure = bindings::vea_error_PLATFORM_FAILURE_ERROR,
}

impl error::Error for VeaError {}

impl VeaError {
    pub(crate) fn new(res: bindings::vea_error_t) -> VeaError {
        VeaError::n(res).unwrap_or_else(|| panic!("Unknown error is reported from VEA: {}", res))
    }
}

impl Display for VeaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::VeaError::*;
        match self {
            IllegalState => write!(f, "illegal state"),
            InvalidArgument => write!(f, "invalid argument"),
            PlatformFailure => write!(f, "platform failure"),
        }
    }
}

/// Represents a notified event from libvda.
#[derive(Debug)]
pub enum Event {
    /// Requests the user to provide input buffers.
    RequireInputBuffers {
        input_count: u32,
        input_frame_width: u32,
        input_frame_height: u32,
        output_buffer_size: u32,
    },
    /// Notifies the user that an input buffer has been processed.
    ProcessedInputBuffer(VeaInputBufferId),
    /// Notifies the user that an output buffer has been processed.
    ProcessedOutputBuffer {
        output_buffer_id: VeaOutputBufferId,
        payload_size: u32,
        key_frame: bool,
        timestamp: i64,
    },
    /// Notifies the result of operation issued by `Session::flush`.
    FlushResponse { flush_done: bool },
    /// Notifies the user of an error.
    NotifyError(VeaError),
}

impl Event {
    /// Creates a new `Event` from a `vea_event_t` instance.
    /// This function is safe if `event` was a value read from libvda's pipe.
    pub(crate) unsafe fn new(event: bindings::vea_event_t) -> Result<Self> {
        use self::Event::*;

        let bindings::vea_event_t {
            event_data,
            event_type,
        } = event;

        match event_type {
            bindings::vea_event_type_REQUIRE_INPUT_BUFFERS => {
                let d = event_data.require_input_buffers;
                Ok(RequireInputBuffers {
                    input_count: d.input_count,
                    input_frame_width: d.input_frame_width,
                    input_frame_height: d.input_frame_height,
                    output_buffer_size: d.output_buffer_size,
                })
            }
            bindings::vea_event_type_PROCESSED_INPUT_BUFFER => {
                Ok(ProcessedInputBuffer(event_data.processed_input_buffer_id))
            }
            bindings::vea_event_type_PROCESSED_OUTPUT_BUFFER => {
                let d = event_data.processed_output_buffer;
                Ok(ProcessedOutputBuffer {
                    output_buffer_id: d.output_buffer_id,
                    payload_size: d.payload_size,
                    key_frame: d.key_frame == 1,
                    timestamp: d.timestamp,
                })
            }
            bindings::vea_event_type_VEA_FLUSH_RESPONSE => Ok(FlushResponse {
                flush_done: event_data.flush_done == 1,
            }),
            bindings::vea_event_type_VEA_NOTIFY_ERROR => {
                Ok(NotifyError(VeaError::new(event_data.error)))
            }
            t => panic!("Unknown event is reported from VEA: {}", t),
        }
    }
}
