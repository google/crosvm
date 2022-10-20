// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a struct for registering signal handlers that get cleared on drop.

use std::convert::TryFrom;
use std::fmt;
use std::io::Cursor;
use std::io::Write;
use std::panic::catch_unwind;
use std::result;

use libc::c_int;
use libc::c_void;
use libc::STDERR_FILENO;
use remain::sorted;
use thiserror::Error;

use super::signal::clear_signal_handler;
use super::signal::has_default_signal_handler;
use super::signal::register_signal_handler;
use super::signal::wait_for_signal;
use super::signal::Signal;
use super::Error as ErrnoError;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Already waiting for interrupt.
    #[error("already waiting for interrupt.")]
    AlreadyWaiting,
    /// Signal already has a handler.
    #[error("signal handler already set for {0:?}")]
    HandlerAlreadySet(Signal),
    /// Failed to check if signal has the default signal handler.
    #[error("failed to check the signal handler for {0:?}: {1}")]
    HasDefaultSignalHandler(Signal, ErrnoError),
    /// Failed to register a signal handler.
    #[error("failed to register a signal handler for {0:?}: {1}")]
    RegisterSignalHandler(Signal, ErrnoError),
    /// Sigaction failed.
    #[error("sigaction failed for {0:?}: {1}")]
    Sigaction(Signal, ErrnoError),
    /// Failed to wait for signal.
    #[error("wait_for_signal failed: {0}")]
    WaitForSignal(ErrnoError),
}

pub type Result<T> = result::Result<T, Error>;

/// The interface used by Scoped Signal handler.
///
/// # Safety
/// The implementation of handle_signal needs to be async signal-safe.
///
/// NOTE: panics are caught when possible because a panic inside ffi is undefined behavior.
pub unsafe trait SignalHandler {
    /// A function that is called to handle the passed signal.
    fn handle_signal(signal: Signal);
}

/// Wrap the handler with an extern "C" function.
extern "C" fn call_handler<H: SignalHandler>(signum: c_int) {
    // Make an effort to surface an error.
    if catch_unwind(|| H::handle_signal(Signal::try_from(signum).unwrap())).is_err() {
        // Note the following cannot be used:
        // eprintln! - uses std::io which has locks that may be held.
        // format! - uses the allocator which enforces mutual exclusion.

        // Get the debug representation of signum.
        let signal: Signal;
        let signal_debug: &dyn fmt::Debug = match Signal::try_from(signum) {
            Ok(s) => {
                signal = s;
                &signal as &dyn fmt::Debug
            }
            Err(_) => &signum as &dyn fmt::Debug,
        };

        // Buffer the output, so a single call to write can be used.
        // The message accounts for 29 chars, that leaves 35 for the string representation of the
        // signal which is more than enough.
        let mut buffer = [0u8; 64];
        let mut cursor = Cursor::new(buffer.as_mut());
        if writeln!(cursor, "signal handler got error for: {:?}", signal_debug).is_ok() {
            let len = cursor.position() as usize;
            // Safe in the sense that buffer is owned and the length is checked. This may print in
            // the middle of an existing write, but that is considered better than dropping the
            // error.
            unsafe {
                libc::write(
                    STDERR_FILENO,
                    cursor.get_ref().as_ptr() as *const c_void,
                    len,
                )
            };
        } else {
            // This should never happen, but write an error message just in case.
            const ERROR_DROPPED: &str = "Error dropped by signal handler.";
            let bytes = ERROR_DROPPED.as_bytes();
            unsafe { libc::write(STDERR_FILENO, bytes.as_ptr() as *const c_void, bytes.len()) };
        }
    }
}

/// Represents a signal handler that is registered with a set of signals that unregistered when the
/// struct goes out of scope. Prefer a signalfd based solution before using this.
pub struct ScopedSignalHandler {
    signals: Vec<Signal>,
}

impl ScopedSignalHandler {
    /// Attempts to register `handler` with the provided `signals`. It will fail if there is already
    /// an existing handler on any of `signals`.
    ///
    /// # Safety
    /// This is safe if H::handle_signal is async-signal safe.
    pub fn new<H: SignalHandler>(signals: &[Signal]) -> Result<Self> {
        let mut scoped_handler = ScopedSignalHandler {
            signals: Vec::with_capacity(signals.len()),
        };
        for &signal in signals {
            if !has_default_signal_handler((signal).into())
                .map_err(|err| Error::HasDefaultSignalHandler(signal, err))?
            {
                return Err(Error::HandlerAlreadySet(signal));
            }
            // Requires an async-safe callback.
            unsafe {
                register_signal_handler((signal).into(), call_handler::<H>)
                    .map_err(|err| Error::RegisterSignalHandler(signal, err))?
            };
            scoped_handler.signals.push(signal);
        }
        Ok(scoped_handler)
    }
}

/// Clears the signal handler for any of the associated signals.
impl Drop for ScopedSignalHandler {
    fn drop(&mut self) {
        for signal in &self.signals {
            if let Err(err) = clear_signal_handler((*signal).into()) {
                eprintln!("Error: failed to clear signal handler: {:?}", err);
            }
        }
    }
}

/// A signal handler that does nothing.
///
/// This is useful in cases where wait_for_signal is used since it will never trigger if the signal
/// is blocked and the default handler may have undesired effects like terminating the process.
pub struct EmptySignalHandler;
/// # Safety
/// Safe because handle_signal is async-signal safe.
unsafe impl SignalHandler for EmptySignalHandler {
    fn handle_signal(_: Signal) {}
}

/// Blocks until SIGINT is received, which often happens because Ctrl-C was pressed in an
/// interactive terminal.
///
/// Note: if you are using a multi-threaded application you need to block SIGINT on all other
/// threads or they may receive the signal instead of the desired thread.
pub fn wait_for_interrupt() -> Result<()> {
    // Register a signal handler if there is not one already so the thread is not killed.
    let ret = ScopedSignalHandler::new::<EmptySignalHandler>(&[Signal::Interrupt]);
    if !matches!(&ret, Ok(_) | Err(Error::HandlerAlreadySet(_))) {
        ret?;
    }

    match wait_for_signal(&[Signal::Interrupt.into()], None) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::WaitForSignal(err)),
    }
}
