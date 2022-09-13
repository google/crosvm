// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::thread;
use std::time::Duration;

use base::named_pipes;
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
        _input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        // TODO(b/171331752): connect filesync functionality.
        _sync: Option<Box<dyn FileSync + Send>>,
        _out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console::new(protection_type, None, out, keep_rds)
    }

    /// Constructs a console with named pipe as input/output connections.
    fn new_with_pipe(
        protection_type: ProtectionType,
        _interrupt_evt: Event,
        pipe_in: named_pipes::PipeConnection,
        pipe_out: named_pipes::PipeConnection,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console::new(
            protection_type,
            Some(ConsoleInput::FromRead(Box::new(pipe_in))),
            Some(Box::new(pipe_out)),
            keep_rds,
        )
    }
}

/// Platform-specific function to add a delay for reading rx.
///
/// We can't issue blocking reads here and overlapped I/O is
/// incompatible with the call site where writes to this pipe are being
/// made, so instead we issue a small wait to prevent us from hogging
/// the CPU. This 20ms delay while typing doesn't seem to be noticeable.
pub(in crate::virtio::console) fn read_delay_if_needed() {
    thread::sleep(Duration::from_millis(20));
}

pub(in crate::virtio::console) fn is_a_fatal_input_error(e: &io::Error) -> bool {
    !matches!(
        e.kind(),
        // Being interrupted is not an error.
        io::ErrorKind::Interrupted |
        // Ignore two kinds of errors on Windows.
        //   - ErrorKind::Other when reading a named pipe before a client connects.
        //   - ErrorKind::WouldBlock when reading a named pipe (we don't use non-blocking I/O).
        io::ErrorKind::Other | io::ErrorKind::WouldBlock
    )
    // Everything else is a fatal input error.
}
