// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base::error;
use base::named_pipes;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use base::WorkerThread;
use sync::Mutex;

use crate::serial_device::SerialInput;
use crate::virtio::console::Console;
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
            Some(Box::new(pipe_in)),
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
fn read_delay_if_needed() {
    thread::sleep(Duration::from_millis(20));
}

fn is_a_fatal_input_error(e: &io::Error) -> bool {
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

/// Starts a thread that reads rx and sends the input back via the returned buffer.
///
/// The caller should listen on `in_avail_evt` for events. When `in_avail_evt` signals that data
/// is available, the caller should lock the returned `Mutex` and read data out of the inner
/// `VecDeque`. The data should be removed from the beginning of the `VecDeque` as it is processed.
///
/// # Arguments
///
/// * `rx` - Data source that the reader thread will wait on to send data back to the buffer
/// * `in_avail_evt` - Event triggered by the thread when new input is available on the buffer
pub(in crate::virtio::console) fn spawn_input_thread(
    mut rx: Box<named_pipes::PipeConnection>,
    in_avail_evt: &Event,
    input_buffer: VecDeque<u8>,
) -> (
    Arc<Mutex<VecDeque<u8>>>,
    WorkerThread<Box<named_pipes::PipeConnection>>,
) {
    let buffer = Arc::new(Mutex::new(input_buffer));
    let buffer_cloned = buffer.clone();

    let thread_in_avail_evt = in_avail_evt
        .try_clone()
        .expect("failed to clone in_avail_evt");

    let res = WorkerThread::start("v_console_input", move |kill_evt| {
        // If there is already data, signal immediately.
        if !buffer.lock().is_empty() {
            thread_in_avail_evt.signal().unwrap();
        }

        match rx.wait_for_client_connection_overlapped_blocking(&kill_evt) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return rx,
            Err(e) => panic!("failed to wait for client: {}", e),
            Ok(()) => (),
        }

        read_input(&mut rx, &thread_in_avail_evt, buffer, kill_evt);
        rx
    });
    (buffer_cloned, res)
}

pub(in crate::virtio::console) fn read_input(
    rx: &mut Box<named_pipes::PipeConnection>,
    thread_in_avail_evt: &Event,
    buffer: Arc<Mutex<VecDeque<u8>>>,
    kill_evt: Event,
) {
    let buffer_max_size = 1 << 12;
    let mut rx_buf = Vec::with_capacity(buffer_max_size);

    let mut read_overlapped =
        named_pipes::OverlappedWrapper::new(true).expect("failed to create OverlappedWrapper");
    loop {
        let size = rx
            .get_available_byte_count()
            .expect("failed to get available byte count") as usize;
        // Clamp to [1, buffer capacity]. Need to read at least one byte so that the read call
        // blocks until data is available.
        let size = std::cmp::min(std::cmp::max(size, 1), buffer_max_size);
        rx_buf.resize(size, Default::default());
        let res = rx.read_overlapped_blocking(&mut rx_buf, &mut read_overlapped, &kill_evt);

        match res {
            Ok(()) => {
                buffer.lock().extend(&rx_buf[..]);
                thread_in_avail_evt.signal().unwrap();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                // Exit event triggered
                break;
            }
            Err(e) => {
                // Being interrupted is not an error, but everything else is.
                if is_a_fatal_input_error(&e) {
                    error!(
                        "failed to read for bytes to queue into console device: {}",
                        e
                    );
                    break;
                }
            }
        }

        // Depending on the platform, a short sleep is needed here (ie. Windows).
        read_delay_if_needed();
    }
}
