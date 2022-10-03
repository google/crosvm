// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::deserialize_and_recv;
use base::named_pipes;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::serialize_and_send;
use base::Error as SysError;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::PipeConnection;
use base::SafeDescriptor;
use base::Tube;
use base::TubeError;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;

pub type PackedTubeResult<T> = Result<T, PackedTubeError>;

#[derive(Debug, ThisError)]
pub enum PackedTubeError {
    #[error("Serializing and recving failed: {0}")]
    DeserializeRecvError(TubeError),
    #[error("Named pipe error: {0}")]
    PipeError(SysError),
    #[error("Serializing and sending failed: {0}")]
    SerializeSendError(TubeError),
}

#[derive(Deserialize, Serialize)]
struct PackedTube {
    tube: Tube,
    server_pipe: PipeConnection,
}

/// Sends a [Tube] through a protocol that expects a [RawDescriptor].
///
/// A packed tube works by creating a named pipe pair, and serializing both the Tube and the
/// server end of the pipe. Then, it returns the client end of the named pipe pair, which can be
/// used as the desired descriptor to send / duplicate to the target.
///
/// The receiver will need to use [packed_tube::unpack] to read the message off the pipe, and thus
/// extract a real [Tube]. It will also read the server end of the pipe, and close it. The
/// `receiver_pid` is the pid of the process that will be unpacking the tube.
///
/// # Safety
/// To prevent dangling handles, the resulting descriptor must be passed to [packed_tube::unpack],
/// in the process which corresponds to `receiver_pid`.
pub unsafe fn pack(tube: Tube, receiver_pid: u32) -> PackedTubeResult<SafeDescriptor> {
    let (server_pipe, client_pipe) = named_pipes::pair(
        &FramingMode::Message,
        &BlockingMode::Wait,
        /* timeout= */ 0,
    )
    .map_err(SysError::from)
    .map_err(PackedTubeError::PipeError)?;

    let packed = PackedTube { tube, server_pipe };

    // Serialize the packed tube, which also duplicates the server end of the pipe into the other
    // process. This lets us drop it on our side without destroying the channel.
    serialize_and_send(
        |buf| packed.server_pipe.write(buf),
        &packed,
        Some(receiver_pid),
    )
    .map_err(PackedTubeError::SerializeSendError)?;

    Ok(SafeDescriptor::from_raw_descriptor(
        client_pipe.into_raw_descriptor(),
    ))
}

/// Unpacks a tube from a client descriptor. This must come from a packed tube.
///
/// # Safety
/// The descriptor passed in must come from [packed_tube::pack].
pub unsafe fn unpack(descriptor: SafeDescriptor) -> PackedTubeResult<Tube> {
    let pipe = PipeConnection::from_raw_descriptor(
        descriptor.into_raw_descriptor(),
        FramingMode::Message,
        BlockingMode::Wait,
    );
    // Safe because we own the descriptor and it came from a PackedTube.
    let unpacked: PackedTube = deserialize_and_recv(|buf| pipe.read(buf))
        .map_err(PackedTubeError::DeserializeRecvError)?;
    // By dropping `unpacked` we close the server end of the pipe.
    Ok(unpacked.tube)
}

#[cfg(test)]
mod tests {
    use base::Tube;

    use crate::packed_tube;

    #[test]
    /// Tests packing and unpacking.
    fn test_pack_unpack() {
        let (tube_server, tube_client) = Tube::pair().unwrap();
        let packed_tube = unsafe { packed_tube::pack(tube_client, std::process::id()).unwrap() };

        // Safe because get_descriptor clones the underlying pipe.
        let recovered_tube = unsafe { packed_tube::unpack(packed_tube).unwrap() };

        let test_message = "Test message".to_string();
        tube_server.send(&test_message).unwrap();
        let received: String = recovered_tube.recv().unwrap();

        assert_eq!(test_message, received);
    }
}
