// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::Event;
use base::FileSync;
use base::RawDescriptor;

use crate::serial_device::SerialInput;
use crate::virtio::console::Console;
use crate::virtio::console::ConsoleInput;
use crate::virtio::ProtectionType;
use crate::SerialDevice;

impl SerialDevice for Console {
    fn new(
        protection_type: ProtectionType,
        _event: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        // TODO(b/171331752): connect filesync functionality.
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console::new(
            protection_type,
            input.map(ConsoleInput::FromRead),
            out,
            keep_rds,
        )
    }
}

/// Platform-specific function to add a delay for reading rx.
///
/// On Unix, this function does nothing.
pub(crate) fn read_delay_if_needed() {}

pub(in crate::virtio::console) fn is_a_fatal_input_error(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::Interrupted
}
