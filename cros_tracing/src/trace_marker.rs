// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

use base::error;
use base::RawDescriptor;

use once_cell::sync::OnceCell;

static TRACE_MARKER_FILE: OnceCell<Mutex<File>> = OnceCell::new();

// Trace marker wrapper macros
#[macro_export]
macro_rules! trace_event {
    ($category:ident, $name:expr) => {
        // TODO(b/259501910) Add support for scoped tracing using a Trace struct
        None as Option<bool>
    };
}

#[macro_export]
macro_rules! trace_event_begin {
    // TODO(b/259501910) Trace marker backend doesn't support trace_event_begin yet
    ($category:ident, $name:expr) => {};
}

#[macro_export]
macro_rules! trace_event_end {
    // TODO(b/259501910) Trace marker backend doesn't support trace_event_end yet
    ($category:ident) => {};
}

#[macro_export]
/// Prints a single non-scoped message without creating a trace context.
macro_rules! trace_simple_print {
    ($($t:tt)*) => {{
        $crate::trace_simple_print(std::format!($($t)*));
    }}
}

#[macro_export]
/// Macro used to handle fd permanency across jailed devices.
/// If we run crosvm without `--disable-sandbox`, we need to add the trace_marker
/// file descriptor to the list of file descriptors allowed to be accessed by the
/// sandboxed process. We call this macro to add the file descriptor to the list
/// of `keep_rds` that the process is allowed to access every time we jail.
macro_rules! push_descriptors {
    ($fd_vec:expr) => {
        $crate::push_descriptors($fd_vec);
    };
}

/// Platform-specific implementation of the `push_descriptors!` macro. If the
/// trace_marker file has been initialized properly, it adds its file descriptor
/// to the list of file descriptors that are allowed to be accessed when the process
/// is jailed in the sandbox.
///
/// # Arguments
///
/// * `keep_rds` - List of file descriptors that will be accessible after jailing
pub fn push_descriptors(keep_rds: &mut Vec<RawDescriptor>) {
    match TRACE_MARKER_FILE.get() {
        Some(file) => {
            let fd = file.lock().unwrap().as_raw_fd();
            if !keep_rds.contains(&fd) {
                keep_rds.push(fd);
            }
        }
        None => {
            error!("Unable to obtain trace_marker descriptor. Was None.");
        }
    }
}

/// Platform-specific implementation of the `trace_simple_print!` macro. If tracing
/// is enabled on the system, it writes the given message to the trace_marker file.
///
/// # Arguments
///
/// * `message` - The message to be written
pub fn trace_simple_print(message: String) {
    // In case tracing is not working or the trace marker file is None we can
    // just ignore this. We don't need to handle the error here.
    if let Some(file) = TRACE_MARKER_FILE.get() {
        // We ignore the error here in case write!() fails, because the trace
        // marker file would be normally closed by the system unless we are
        // actively tracing the runtime. It is not an error.
        write!(file.lock().unwrap(), "{}", message).ok();
    };
}

/// Initializes the trace_marker backend. It attepts to open the trace_marker
/// file and keep a reference that can be shared throughout the lifetime of the
/// crosvm process.
///
/// If tracefs is not available on the system or the file cannot be opened,
/// tracing will not work but the crosvm process will still continue execution
/// without tracing.
pub fn init() {
    let path = Path::new("/sys/kernel/tracing/trace_marker");
    let file = if path.exists() {
        match OpenOptions::new().read(false).write(true).open(path) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed opening the trace_marker file: {}. Tracing will not work.",
                    e
                );
                return;
            }
        }
    } else {
        error!("Could not find trace_marker location. Tracing will not work.");
        return;
    };

    if TRACE_MARKER_FILE.set(Mutex::new(file)).is_err() {
        error!("Failed to create mutex. Tracing will not work.");
    }
}

pub struct Trace {}

impl Trace {
    pub fn start() -> anyhow::Result<Self> {
        Ok(Self {})
    }

    pub fn end(self) {}
}

impl Drop for Trace {
    fn drop(&mut self) {
        // TODO(b/259501910) - Add support for dropping traces
    }
}
