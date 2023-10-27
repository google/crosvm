// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::Event;
use base::FileSync;
use base::RawDescriptor;
use hypervisor::ProtectionType;

use crate::serial_device::SerialInput;
use crate::serial_device::SerialOptions;
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
        _protection_type: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        _sync: Option<Box<dyn FileSync + Send>>,
        options: SerialOptions,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Serial {
        Serial::new_common(interrupt_evt, input, out, options.out_timestamp)
    }
}
