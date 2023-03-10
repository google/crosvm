// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "gpu")]
pub(crate) mod gpu;

use std::io::Result;
use std::mem::size_of;
use std::path::Path;

use base::named_pipes::OverlappedWrapper;
use base::{Event, PipeConnection};

use crate::client::HandleRequestResult;
use crate::VmRequest;

pub const SERVICE_MESSAGE_HEADER_SIZE: usize = size_of::<u32>();

// TODO(b/145563346): Make this work on Windows
pub fn handle_request<T: AsRef<Path> + std::fmt::Debug>(
    _request: &VmRequest,
    _socket_path: T,
) -> HandleRequestResult {
    Err(())
}

/// Send the size header first and then the protbuf message.
///
/// A helper function to keep communication with service consistent across crosvm code.
pub fn send_service_message(
    connection: &mut PipeConnection,
    message: &[u8],
    overlapped_wrapper: &mut OverlappedWrapper,
) -> Result<()> {
    let size_in_bytes = message.len() as u32;

    connection
        .write_overlapped_blocking_message(&size_in_bytes.to_be_bytes(), overlapped_wrapper)?;
    connection.write_overlapped_blocking_message(message, overlapped_wrapper)?;
    Ok(())
}

/// Read and wait for the header to arrive in the named pipe. Once header is available, use the
/// size to fetch the message.
///
/// A helper function to keep communication with service consistent across crosvm code.
pub fn recv_service_message(
    connection: &mut PipeConnection,
    overlapped_wrapper: &mut OverlappedWrapper,
    exit_event: &Event,
) -> Result<Vec<u8>> {
    connection.read_overlapped_blocking_message(
        SERVICE_MESSAGE_HEADER_SIZE,
        |bytes: &[u8]| {
            assert_eq!(bytes.len(), SERVICE_MESSAGE_HEADER_SIZE);
            u32::from_be_bytes(bytes.try_into().expect("failed to get array from slice")) as usize
        },
        overlapped_wrapper,
        exit_event,
    )
}
