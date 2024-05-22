// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "gpu")]
pub(crate) mod gpu;

use std::io::Result;
use std::mem::size_of;
use std::path::Path;

use base::error;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::named_pipes::MultiPartMessagePipe;
use base::named_pipes::OverlappedWrapper;
use base::Error;
use base::Event;
use base::PipeTube;
use hypervisor::MemCacheType;
use hypervisor::MemSlot;
use hypervisor::Vm;
use resources::Alloc;
use resources::SystemAllocator;

use crate::client::HandleRequestResult;
use crate::VmRequest;

pub const SERVICE_MESSAGE_HEADER_SIZE: usize = size_of::<u32>();

pub fn handle_request<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
) -> HandleRequestResult {
    match base::named_pipes::create_client_pipe(
        socket_path
            .as_ref()
            .to_str()
            .expect("socket path must be a string"),
        &FramingMode::Message,
        &BlockingMode::Wait,
        /* overlapped= */ false,
    ) {
        Ok(pipe) => {
            let tube = PipeTube::from(pipe, None);
            if let Err(e) = tube.send(request) {
                error!(
                    "failed to send request to pipe at '{:?}': {}",
                    socket_path, e
                );
                return Err(());
            }
            match tube.recv() {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!(
                        "failed to recv response from pipe at '{:?}': {}",
                        socket_path, e
                    );
                    Err(())
                }
            }
        }
        Err(e) => {
            error!("failed to connect to socket at '{:?}': {}", socket_path, e);
            Err(())
        }
    }
}

/// Send the size header first and then the protbuf message.
///
/// A helper function to keep communication with service consistent across crosvm code.
pub fn send_service_message(
    connection: &MultiPartMessagePipe,
    message: &[u8],
    overlapped_wrapper: &mut OverlappedWrapper,
) -> Result<()> {
    let size_in_bytes = message.len() as u32;
    connection.write_overlapped_blocking_message(
        &size_in_bytes.to_be_bytes(),
        message,
        overlapped_wrapper,
    )
}

/// Read and wait for the header to arrive in the named pipe. Once header is available, use the
/// size to fetch the message.
///
/// A helper function to keep communication with service consistent across crosvm code.
pub fn recv_service_message(
    connection: &MultiPartMessagePipe,
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

pub fn should_prepare_memory_region() -> bool {
    false
}

pub fn prepare_shared_memory_region(
    _vm: &mut dyn Vm,
    _allocator: &mut SystemAllocator,
    _alloc: Alloc,
    _cache: MemCacheType,
) -> std::result::Result<(u64, MemSlot), Error> {
    unimplemented!()
}

/// State of a specific audio device on boot.
pub struct InitialAudioSessionState {
    // Uniquely identify an audio device.
    pub device_index: usize,
    // GUID assigned to the device's IAudioClient
    pub audio_client_guid: String,
}
