// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::named_pipes;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::AsRawDescriptor;
pub use base::Console as ConsoleInput;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use hypervisor::ProtectionType;

use crate::serial_device::Error;
use crate::serial_device::SerialInput;
use crate::serial_device::SerialOptions;
use crate::serial_device::SerialParameters;

pub const SYSTEM_SERIAL_TYPE_NAME: &str = "NamedPipe";

/// Abstraction over serial-like devices that can be created given an event and optional input and
/// output streams.
pub trait SerialDevice {
    fn new(
        protection_type: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        options: SerialOptions,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
    fn new_with_pipe(
        protection_type: ProtectionType,
        interrupt_evt: Event,
        pipe_in: named_pipes::PipeConnection,
        pipe_out: named_pipes::PipeConnection,
        options: SerialOptions,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
}

pub(crate) fn create_system_type_serial_device<T: SerialDevice>(
    param: &SerialParameters,
    protection_type: ProtectionType,
    evt: Event,
    _input: Option<Box<dyn SerialInput>>,
    keep_rds: &mut Vec<RawDescriptor>,
) -> std::result::Result<T, Error> {
    match &param.path {
        None => Err(Error::PathRequired),
        Some(path) => {
            // Note that when this pipe is not connected, the serial device will
            // discard output. If the pipe's buffer is allowed to fill, writes
            // will block, which will stall the output queue. This generally
            // points to a bug in the named pipe consumer, and if desired we
            // could address it in CrosVM by adding a write timeout.
            let pipe_in = named_pipes::create_server_pipe(
                path.to_str().unwrap(),
                &FramingMode::Byte,
                &BlockingMode::Wait,
                /* timeout= */ 0,
                named_pipes::DEFAULT_BUFFER_SIZE,
                /* overlapped= */ true,
            )
            .map_err(Error::SystemTypeError)?;

            let pipe_out = pipe_in.try_clone().map_err(Error::SystemTypeError)?;

            keep_rds.push(pipe_in.as_raw_descriptor());
            keep_rds.push(pipe_out.as_raw_descriptor());

            Ok(T::new_with_pipe(
                protection_type,
                evt,
                pipe_in,
                pipe_out,
                Default::default(),
                keep_rds.to_vec(),
            ))
        }
    }
}
