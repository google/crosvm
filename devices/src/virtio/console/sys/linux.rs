// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base::error;
use base::Event;
use base::EventToken;
use base::FileSync;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use sync::Mutex;

use crate::serial::sys::InStreamType;
use crate::serial_device::SerialInput;
use crate::serial_device::SerialOptions;
use crate::virtio::console::Console;
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
        options: SerialOptions,
        keep_rds: Vec<RawDescriptor>,
    ) -> Console {
        Console::new(protection_type, input, out, keep_rds, options.pci_address)
    }
}

fn is_a_fatal_input_error(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::Interrupted
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
    mut rx: InStreamType,
    in_avail_evt: &Event,
    input_buffer: VecDeque<u8>,
) -> (Arc<Mutex<VecDeque<u8>>>, WorkerThread<InStreamType>) {
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
        read_input(&mut rx, &thread_in_avail_evt, buffer, kill_evt);
        rx
    });
    (buffer_cloned, res)
}

pub(in crate::virtio::console) fn read_input(
    rx: &mut InStreamType,
    thread_in_avail_evt: &Event,
    buffer: Arc<Mutex<VecDeque<u8>>>,
    kill_evt: Event,
) {
    #[derive(EventToken)]
    enum Token {
        ConsoleEvent,
        Kill,
    }

    let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
        (&kill_evt, Token::Kill),
        (rx.get_read_notifier(), Token::ConsoleEvent),
    ]) {
        Ok(ctx) => ctx,
        Err(e) => {
            error!("failed creating WaitContext {:?}", e);
            return;
        }
    };

    let mut kill_timeout = None;
    let mut rx_buf = [0u8; 1 << 12];
    'wait: loop {
        let events = match wait_ctx.wait() {
            Ok(events) => events,
            Err(e) => {
                error!("Failed to wait for events. {}", e);
                return;
            }
        };
        for event in events.iter() {
            match event.token {
                Token::Kill => {
                    // Ignore the kill event until there are no other events to process so that
                    // we drain `rx` as much as possible. The next `wait_ctx.wait()` call will
                    // immediately re-entry this case since we don't call `kill_evt.wait()`.
                    if events.iter().all(|e| matches!(e.token, Token::Kill)) {
                        break 'wait;
                    }
                    const TIMEOUT_DURATION: Duration = Duration::from_millis(500);
                    match kill_timeout {
                        None => {
                            kill_timeout = Some(Instant::now() + TIMEOUT_DURATION);
                        }
                        Some(t) => {
                            if Instant::now() >= t {
                                error!(
                                    "failed to drain console input within {:?}, giving up",
                                    TIMEOUT_DURATION
                                );
                                break 'wait;
                            }
                        }
                    }
                }
                Token::ConsoleEvent => {
                    match rx.read(&mut rx_buf) {
                        Ok(0) => break 'wait, // Assume the stream of input has ended.
                        Ok(size) => {
                            buffer.lock().extend(&rx_buf[0..size]);
                            thread_in_avail_evt.signal().unwrap();
                        }
                        Err(e) => {
                            // Being interrupted is not an error, but everything else is.
                            if is_a_fatal_input_error(&e) {
                                error!(
                                    "failed to read for bytes to queue into console device: {}",
                                    e
                                );
                                break 'wait;
                            }
                        }
                    }
                }
            }
        }
    }
}
