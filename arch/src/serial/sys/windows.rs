// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]

use std::io::Read;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base::RawDescriptor;
use base::Result;
use devices::serial_device::SerialParameters;
use devices::serial_device::SerialType;
use devices::Bus;
use devices::Serial;
use jail::FakeMinijailStub as Minijail;
use sync::Mutex;

use crate::serial::SERIAL_ADDR;
use crate::DeviceRegistrationError;

/// A type for queueing input bytes to a serial device that abstracts if the device is local or part
/// of a sandboxed device process.
/// TODO(b/160806152) rizhang: Move to different file for readability.
pub enum SerialInput {
    #[doc(hidden)]
    Local(Arc<Mutex<Serial>>),
}

impl SerialInput {
    /// Creates a `SerialInput` that trivially forwards queued bytes to the device in the local
    /// process.
    pub fn new_local(serial: Arc<Mutex<Serial>>) -> SerialInput {
        SerialInput::Local(serial)
    }

    /// Just like `Serial::queue_input_bytes`, but abstracted over local and sandboxed serial
    /// devices.
    pub fn queue_input_bytes(&self, bytes: &[u8]) -> Result<()> {
        match self {
            SerialInput::Local(device) => device.lock().queue_input_bytes(bytes),
        }
    }
}

pub fn add_serial_device(
    com_num: usize,
    com: Serial,
    serial_params: &SerialParameters,
    serial_jail: Option<Minijail>,
    _preserved_descriptors: Vec<RawDescriptor>,
    io_bus: &Bus,
) -> std::result::Result<(), DeviceRegistrationError> {
    match serial_jail {
        Some(_) => (),
        None => {
            let com = Arc::new(Mutex::new(com));
            io_bus
                .insert(com.clone(), SERIAL_ADDR[com_num], 0x8)
                .unwrap();

            if !serial_params.stdin {
                if let SerialType::SystemSerialType = serial_params.type_ {
                    let mut in_pipe_result = com
                        .lock()
                        .system_params
                        .in_stream
                        .as_ref()
                        .unwrap()
                        .try_clone();
                    thread::spawn(move || {
                        let serial_input = SerialInput::new_local(com);
                        let in_pipe = in_pipe_result.as_mut().unwrap();

                        let mut buffer: [u8; 255] = [0; 255];
                        loop {
                            // Safe because we are reading bytes.
                            let bytes = in_pipe.read(&mut buffer).unwrap_or(0);
                            if bytes > 0 {
                                serial_input.queue_input_bytes(&buffer[0..bytes]).unwrap();
                            }
                            // We can't issue blocking reads here and overlapped I/O is
                            // incompatible with the call site where writes to this pipe are being
                            // made, so instead we issue a small wait to prevent us from hogging
                            // the CPU. This 20ms delay while typing doesn't seem to be noticeable.
                            thread::sleep(Duration::from_millis(20));
                        }
                    });
                }
            }
        }
    }
    Ok(())
}
