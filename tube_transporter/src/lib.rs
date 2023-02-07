// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Do nothing on unix as tube_transporter is windows only.
#![cfg(windows)]

//! This IPC crate is used by the broker process to send boot data across the
//! different crosvm child processes on Windows.

use std::fmt;
use std::fmt::Display;

use base::deserialize_and_recv;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::named_pipes::PipeConnection;
use base::serialize_and_send;
use base::set_alias_pid;
use base::set_duplicate_handle_tube;
use base::DuplicateHandleTube;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::Tube;
use base::TubeError;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;

pub mod packed_tube;

pub type TransportTubeResult<T> = std::result::Result<T, TubeTransportError>;

/// Contains information for a child process to set up the Tube for use.
#[derive(Serialize, Deserialize, Debug)]
pub struct TubeTransferData {
    // Tube to be sent to the child process.
    pub tube: Tube,
    // Used to determine what the Tube's purpose is.
    pub tube_token: TubeToken,
}

#[derive(Debug, ThisError)]
pub enum TubeTransportError {
    #[error("Serializing and sending failed: {0}")]
    SerializeSendError(TubeError),
    #[error("Serializing and recving failed: {0}")]
    DeserializeRecvError(TubeError),
    #[error("Tube with token {0} not found")]
    TubeNotFound(TubeToken),
}

/// The target child process will use this decide what a Tube's purpose is.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum TubeToken {
    Bootstrap,
    Control,
    Ipc,
    VhostUser,
}

impl Display for TubeToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransportData {
    dh_tube: Option<Tube>,
    alias_pid: Option<u32>,
    // A list Tubes and related metadata to transfer. This list should not be emptied, since
    // that would cause a Tube to drop and thus closing the Tube.
    tube_transfer_data_list: Vec<TubeTransferData>,
}

/// Used by the Broker process to transport Tubes to a target child process.
pub struct TubeTransporter {
    pipe_connection: PipeConnection,
    transport_data: TransportData,
}

impl TubeTransporter {
    /// WARNING: PipeConnection must be a message mode, blocking pipe.
    pub fn new(
        pipe_connection: PipeConnection,
        tube_transfer_data_list: Vec<TubeTransferData>,
        alias_pid: Option<u32>,
        dh_tube: Option<Tube>,
    ) -> TubeTransporter {
        return TubeTransporter {
            pipe_connection,
            transport_data: TransportData {
                dh_tube,
                alias_pid,
                tube_transfer_data_list,
            },
        };
    }

    /// Sends tubes to the other end of the pipe. Note that you must provide the destination
    /// PID so that descriptors can be sent.
    pub fn serialize_and_transport(&self, child_pid: u32) -> TransportTubeResult<()> {
        serialize_and_send(
            |buf| self.pipe_connection.write(buf),
            &self.transport_data,
            /* target_pid= */ Some(child_pid),
        )
        .map_err(TubeTransportError::SerializeSendError)?;
        Ok(())
    }

    pub fn push_tube(&mut self, tube: Tube, tube_token: TubeToken) {
        self.transport_data
            .tube_transfer_data_list
            .push(TubeTransferData { tube, tube_token });
    }
}

/// Used by the child process to read Tubes sent from the Broker.
pub struct TubeTransporterReader {
    reader_pipe_connection: PipeConnection,
}

impl TubeTransporterReader {
    /// WARNING: PipeConnection must be a message mode, blocking pipe.
    pub fn create_tube_transporter_reader(pipe_connection: PipeConnection) -> Self {
        TubeTransporterReader {
            reader_pipe_connection: pipe_connection,
        }
    }

    pub fn read_tubes(&self) -> TransportTubeResult<TubeTransferDataList> {
        let res: TransportData =
            deserialize_and_recv(|buf| unsafe { self.reader_pipe_connection.read(buf) })
                .map_err(TubeTransportError::DeserializeRecvError)?;

        if let Some(tube) = res.dh_tube {
            let dh_tube = DuplicateHandleTube::new(tube);
            set_duplicate_handle_tube(dh_tube);
        }
        if let Some(alias_pid) = res.alias_pid {
            set_alias_pid(alias_pid);
        }
        return Ok(TubeTransferDataList(res.tube_transfer_data_list));
    }
}

impl FromRawDescriptor for TubeTransporterReader {
    /// Creates a TubeTransporterReader from a raw descriptor.
    /// # Safety
    /// 1. descriptor is valid & ownership is released to the TubeTransporterReader
    ///
    /// # Avoiding U.B.
    /// 1. The underlying pipe is a message pipe in wait mode.
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        TubeTransporterReader::create_tube_transporter_reader(PipeConnection::from_raw_descriptor(
            descriptor,
            FramingMode::Message,
            BlockingMode::Wait,
        ))
    }
}

#[derive(Debug)]
pub struct TubeTransferDataList(Vec<TubeTransferData>);

impl TubeTransferDataList {
    pub fn get_tube(&mut self, token: TubeToken) -> TransportTubeResult<Tube> {
        Ok(self
            .0
            .remove(
                match self
                    .0
                    .iter()
                    .position(|tube_data| tube_data.tube_token == token)
                {
                    Some(pos) => pos,
                    None => return Err(TubeTransportError::TubeNotFound(token)),
                },
            )
            .tube)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use base::named_pipes::pair;
    use base::named_pipes::BlockingMode;
    use base::named_pipes::FramingMode;
    use base::Event;
    use base::EventWaitResult;
    use winapi::um::processthreadsapi::GetCurrentProcessId;

    use super::*;

    #[test]
    fn test_send_tubes_through_tube_transporter() {
        let (broker_pipe_connection_server, child_process_pipe) = pair(
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
        )
        .unwrap();

        // Start a thread to simulate a new process. This thread will attempt to read the Tubes
        // from the pipe.
        let child_join_handle = thread::Builder::new()
            .name("Sandboxed child process listening thread".to_string())
            .spawn(move || {
                let child_process_pipe = child_process_pipe;
                let transporter_reader =
                    TubeTransporterReader::create_tube_transporter_reader(child_process_pipe);
                let tube_data_list = transporter_reader.read_tubes().unwrap();
                return tube_data_list;
            })
            .unwrap();

        // Safe because this kernel function just returns the current PID.
        //
        // We want to get the current PID as a sanity check for the `OpenProcess` call
        // when duplicating a handle through a Tube.
        let current_pid = unsafe { GetCurrentProcessId() };

        // We want the test to drop device_tube_1 and 2 after transportation is complete. Since
        // Tubes have many SafeDescriptors, we still want Tubes to work even if their original
        // handles are closed.
        let (main_tube_1, main_tube_2) = {
            let (main_tube_1, device_tube_1) = Tube::pair().unwrap();
            let (main_tube_2, device_tube_2) = Tube::pair().unwrap();

            let tube_transporter = TubeTransporter::new(
                broker_pipe_connection_server,
                vec![
                    TubeTransferData {
                        tube: device_tube_1,
                        tube_token: TubeToken::Control,
                    },
                    TubeTransferData {
                        tube: device_tube_2,
                        tube_token: TubeToken::Ipc,
                    },
                ],
                /* alias_pid= */
                None,
                /* dh_tube= */
                None,
            );

            // TODO: we just test within the same process here, so we send to ourselves.
            tube_transporter
                .serialize_and_transport(current_pid)
                .expect("serialize and transporting failed");

            (main_tube_1, main_tube_2)
        };

        let tube_data_list = child_join_handle.join().unwrap().0;
        assert_eq!(tube_data_list.len(), 2);
        assert_eq!(tube_data_list[0].tube_token, TubeToken::Control);
        assert_eq!(tube_data_list[1].tube_token, TubeToken::Ipc);

        // Test sending a string through the Tubes
        tube_data_list[0]
            .tube
            .send(&"hello main 1".to_string())
            .expect("tube 1 failed to send");
        tube_data_list[1]
            .tube
            .send(&"hello main 2".to_string())
            .expect("tube 2 failed to send.");

        assert_eq!(main_tube_1.recv::<String>().unwrap(), "hello main 1");
        assert_eq!(main_tube_2.recv::<String>().unwrap(), "hello main 2");

        // Test sending a handle through a Tube. Note that the Tube in `tube_data_list[1]` can't
        // send a handle across because `CHILD_PID` isn't mapped to a real process.
        let event_handle = Event::new().unwrap();

        tube_data_list[0]
            .tube
            .send(&event_handle)
            .expect("tube 1 failed to send");

        let duped_handle = main_tube_1.recv::<Event>().unwrap();

        event_handle.write(1).unwrap();

        assert!(matches!(
            duped_handle
                .read_timeout(std::time::Duration::from_millis(2000))
                .unwrap(),
            EventWaitResult::Signaled
        ));
    }
}
