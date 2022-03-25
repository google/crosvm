// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::serial_device::{Error, SerialParameters};
use base::named_pipes;
use base::named_pipes::{BlockingMode, FramingMode};
use base::FileSync;
use base::{AsRawDescriptor, Event, RawDescriptor};
use hypervisor::ProtectionType;
use std::io::{self};
use std::path::Path;

pub use base::Console as ConsoleInput;

pub const SYSTEM_SERIAL_TYPE_NAME: &str = "NamedPipe";

/// Abstraction over serial-like devices that can be created given an event and optional input and
/// output streams.
pub trait SerialDevice {
    fn new(
        protected_vm: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
    fn new_pipe(
        protected_vm: ProtectionType,
        interrupt_evt: Event,
        pipe_in: named_pipes::PipeConnection,
        pipe_out: named_pipes::PipeConnection,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
}

pub(crate) fn create_system_type_serial_device<T: SerialDevice>(
    param: &SerialParameters,
    protected_vm: ProtectionType,
    evt: Event,
    _input: Option<Box<dyn io::Read + Send>>,
    keep_rds: &mut Vec<RawDescriptor>,
) -> std::result::Result<T, Error> {
    match &param.path {
        None => return Err(Error::PathRequired),
        Some(path) => {
            // We must create this pipe in non-blocking mode because a blocking
            // read in one thread will block a write in another thread having a
            // handle to the same end of the pipe, which will hang the
            // emulator. This does mean that the event loop writing to the
            // pipe's output will need to swallow errors caused by writing to
            // the pipe when it's not ready; but in practice this does not seem
            // to cause a problem.
            let pipe_in = named_pipes::create_server_pipe(
                path.to_str().unwrap(),
                &FramingMode::Byte,
                &BlockingMode::NoWait,
                0, // default timeout
                named_pipes::DEFAULT_BUFFER_SIZE,
                false,
            )
            .map_err(Error::SystemTypeError)?;

            let pipe_out = pipe_in.try_clone().map_err(Error::SystemTypeError)?;

            keep_rds.push(pipe_in.as_raw_descriptor());
            keep_rds.push(pipe_out.as_raw_descriptor());

            return Ok(T::new_pipe(
                protected_vm,
                evt,
                pipe_in,
                pipe_out,
                keep_rds.to_vec(),
            ));
        }
    }
}
