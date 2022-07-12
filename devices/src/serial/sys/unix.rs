// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::{Event, FileSync, RawDescriptor, Result};
use hypervisor::ProtectionType;

use crate::serial_device::SerialInput;
use crate::sys::serial_device::SerialDevice;
use crate::Serial;

// TODO(b/234469655): Remove type alias once ReadNotifier is implemented for
// PipeConnection.
pub(crate) type InStreamType = Box<dyn SerialInput>;

impl SerialDevice for Serial {
    /// Constructs a Serial device ready for input and output.
    ///
    /// The stream `input` should not block, instead returning 0 bytes if are no bytes available.
    fn new(
        _protected_vm: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Serial {
        Serial::new_common(interrupt_evt, input, out)
    }
}

impl Serial {
    pub(in crate::serial) fn system_handle_write(&mut self, v: u8) -> Result<()> {
        if let Some(out) = self.out.as_mut() {
            out.write_all(&[v])?;
            out.flush()?;
        }
        Ok(())
    }
}
