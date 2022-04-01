// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Events reported by VDA over pipe FD.

use enumn::N;
use std::fmt::{self, Display};

use super::bindings;
use crate::error::*;

/// Represents a response from libvda.
///
/// Each value corresponds to a value of [`VideoDecodeAccelerator::Result`](https://cs.chromium.org/chromium/src/components/arc/common/video_decode_accelerator.mojom?rcl=128dc1f18791dc4593b9fd671aab84cb72bf6830&l=84).
#[derive(Debug, Clone, Copy, N)]
#[repr(u32)]
pub enum Response {
    Success = bindings::vda_result_SUCCESS,
    IllegalState = bindings::vda_result_ILLEGAL_STATE,
    InvalidArgument = bindings::vda_result_INVALID_ARGUMENT,
    UnreadableInput = bindings::vda_result_UNREADABLE_INPUT,
    PlatformFailure = bindings::vda_result_PLATFORM_FAILURE,
    InsufficientResources = bindings::vda_result_INSUFFICIENT_RESOURCES,
    Cancelled = bindings::vda_result_CANCELLED,
}

impl Response {
    pub(crate) fn new(res: bindings::vda_result_t) -> Response {
        Response::n(res).unwrap_or_else(|| panic!("Unknown response is reported from VDA: {}", res))
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Response::*;
        match self {
            Success => write!(f, "success"),
            IllegalState => write!(f, "illegal state"),
            InvalidArgument => write!(f, "invalid argument"),
            UnreadableInput => write!(f, "unreadable input"),
            PlatformFailure => write!(f, "platform failure"),
            InsufficientResources => write!(f, "insufficient resources"),
            Cancelled => write!(f, "cancelled"),
        }
    }
}

impl From<Response> for Result<()> {
    fn from(r: Response) -> Self {
        match r {
            Response::Success => Ok(()),
            _ => Err(Error::LibVdaFailure(r)),
        }
    }
}

/// Represents a notified event from libvda.
#[derive(Debug)]
pub enum Event {
    /// Requests the users to provide output buffers.
    ProvidePictureBuffers {
        min_num_buffers: u32,
        width: i32,
        height: i32,
        visible_rect_left: i32,
        visible_rect_top: i32,
        visible_rect_right: i32,
        visible_rect_bottom: i32,
    },
    /// Notifies the user of a decoded frame ready for display.
    /// These events will arrive in display order.
    PictureReady {
        buffer_id: i32,
        bitstream_id: i32,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    },
    /// Notifies the end of bitstream buffer.
    NotifyEndOfBitstreamBuffer {
        bitstream_id: i32,
    },
    NotifyError(Response),
    /// Notifies the result of operation issued by `Session::reset`.
    ResetResponse(Response),
    /// Notifies the result of operation issued by `Session::flush`.
    FlushResponse(Response),
}

impl Event {
    /// Creates a new `Event` from a `vda_event_t` instance.
    /// This function is safe if `event` was a value read from libvda's pipe.
    pub(crate) unsafe fn new(event: bindings::vda_event_t) -> Result<Event> {
        use self::Event::*;

        let data = event.event_data;
        match event.event_type {
            bindings::vda_event_type_PROVIDE_PICTURE_BUFFERS => {
                let d = data.provide_picture_buffers;
                Ok(ProvidePictureBuffers {
                    min_num_buffers: d.min_num_buffers,
                    width: d.width,
                    height: d.height,
                    visible_rect_left: d.visible_rect_left,
                    visible_rect_top: d.visible_rect_top,
                    visible_rect_right: d.visible_rect_right,
                    visible_rect_bottom: d.visible_rect_bottom,
                })
            }
            bindings::vda_event_type_PICTURE_READY => {
                let d = data.picture_ready;
                Ok(PictureReady {
                    buffer_id: d.picture_buffer_id,
                    bitstream_id: d.bitstream_id,
                    left: d.crop_left,
                    top: d.crop_top,
                    right: d.crop_right,
                    bottom: d.crop_bottom,
                })
            }
            bindings::vda_event_type_NOTIFY_END_OF_BITSTREAM_BUFFER => {
                Ok(NotifyEndOfBitstreamBuffer {
                    bitstream_id: data.bitstream_id,
                })
            }
            bindings::vda_event_type_NOTIFY_ERROR => Ok(NotifyError(Response::new(data.result))),
            bindings::vda_event_type_RESET_RESPONSE => {
                Ok(ResetResponse(Response::new(data.result)))
            }
            bindings::vda_event_type_FLUSH_RESPONSE => {
                Ok(FlushResponse(Response::new(data.result)))
            }
            t => panic!("Unknown event is reported from VDA: {}", t),
        }
    }
}
