// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::AsRawDescriptor;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use base::ReadNotifier;
use hypervisor::ProtectionType;

use crate::serial_device::Error;
use crate::serial_device::SerialInput;
use crate::serial_device::SerialOptions;
use crate::serial_device::SerialParameters;

pub const SYSTEM_SERIAL_TYPE_NAME: &str = "UnixSocket";

// This wrapper is used in place of the libstd native version because we don't want
// buffering for stdin.
pub struct ConsoleInput(std::io::Stdin);

impl ConsoleInput {
    pub fn new() -> Self {
        Self(std::io::stdin())
    }
}

impl io::Read for ConsoleInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.0.read(out)
    }
}

impl ReadNotifier for ConsoleInput {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.0
    }
}

impl SerialInput for ConsoleInput {}

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
}

pub(crate) fn create_system_type_serial_device<T: SerialDevice>(
    _param: &SerialParameters,
    _protection_type: ProtectionType,
    _evt: Event,
    _input: Option<Box<dyn SerialInput>>,
    _keep_rds: &mut Vec<RawDescriptor>,
) -> std::result::Result<T, Error> {
    Err(Error::Unimplemented(
        crate::serial_device::SerialType::SystemSerialType,
    ))
}

/// Creates a serial device that use the given UnixStream path for both input and output.
pub(crate) fn create_unix_stream_serial_device<T: SerialDevice>(
    _param: &SerialParameters,
    _protection_type: ProtectionType,
    _evt: Event,
    _keep_rds: &mut Vec<RawDescriptor>,
) -> std::result::Result<T, Error> {
    Err(Error::Unimplemented(
        crate::serial_device::SerialType::UnixStream,
    ))
}
