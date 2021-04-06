// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a struct for registering signal handlers that get cleared on drop.

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::io::{Cursor, Write};
use std::panic::catch_unwind;
use std::result;

use libc::{c_int, c_void, STDERR_FILENO};

use crate::errno;
use crate::signal::{
    clear_signal_handler, has_default_signal_handler, register_signal_handler, wait_for_signal,
    Signal,
};

#[derive(Debug)]
pub enum Error {
    /// Sigaction failed.
    Sigaction(Signal, errno::Error),
    /// Failed to check if signal has the default signal handler.
    HasDefaultSignalHandler(Signal, errno::Error),
    /// Failed to register a signal handler.
    RegisterSignalHandler(Signal, errno::Error),
    /// Signal already has a handler.
    HandlerAlreadySet(Signal),
    /// Already waiting for interrupt.
    AlreadyWaiting,
    /// Failed to wait for signal.
    WaitForSignal(errno::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Sigaction(s, e) => write!(f, "sigaction failed for {0:?}: {1}", s, e),
            HasDefaultSignalHandler(s, e) => {
                write!(f, "failed to check the signal handler for {0:?}: {1}", s, e)
            }
            RegisterSignalHandler(s, e) => write!(
                f,
                "failed to register a signal handler for {0:?}: {1}",
                s, e
            ),
            HandlerAlreadySet(s) => write!(f, "signal handler already set for {0:?}", s),
            AlreadyWaiting => write!(f, "already waiting for interrupt."),
            WaitForSignal(e) => write!(f, "wait_for_signal failed: {0}", e),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::mem::zeroed;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, Once};
    use std::thread::{sleep, spawn};
    use std::time::{Duration, Instant};

    use libc::sigaction;

    use crate::{gettid, kill, Pid};

    const TEST_SIGNAL: Signal = Signal::User1;
    const TEST_SIGNALS: &[Signal] = &[Signal::User1, Signal::User2];

    static TEST_SIGNAL_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Only allows one test case to execute at a time.
    fn get_mutex() -> MutexGuard<'static, ()> {
        static INIT: Once = Once::new();
        static mut VAL: Option<Arc<Mutex<()>>> = None;

        INIT.call_once(|| {
            let val = Some(Arc::new(Mutex::new(())));
            // Safe because the mutation is protected by the Once.
            unsafe { VAL = val }
        });

        // Safe mutation only happens in the Once.
        unsafe { VAL.as_ref() }.unwrap().lock().unwrap()
    }

    fn reset_counter() {
        TEST_SIGNAL_COUNTER.swap(0, Ordering::SeqCst);
    }

    fn get_sigaction(signal: Signal) -> Result<sigaction> {
        // Safe because sigaction is owned and expected to be initialized ot zeros.
        let mut sigact: sigaction = unsafe { zeroed() };

        if unsafe { sigaction(signal.into(), null(), &mut sigact) } < 0 {
            Err(Error::Sigaction(signal, errno::Error::last()))
        } else {
            Ok(sigact)
        }
    }

    /// Safety:
    /// This is only safe if the signal handler set in sigaction is safe.
    unsafe fn restore_sigaction(signal: Signal, sigact: sigaction) -> Result<sigaction> {
        if sigaction(signal.into(), &sigact, null_mut()) < 0 {
            Err(Error::Sigaction(signal, errno::Error::last()))
        } else {
            Ok(sigact)
        }
    }

    /// Safety:
    /// Safe if the signal handler for Signal::User1 is safe.
    unsafe fn send_test_signal() {
        kill(gettid(), Signal::User1.into()).unwrap()
    }

    macro_rules! assert_counter_eq {
        ($compare_to:expr) => {{
            let expected: usize = $compare_to;
            let got: usize = TEST_SIGNAL_COUNTER.load(Ordering::SeqCst);
            if got != expected {
                panic!(
                    "wrong signal counter value: got {}; expected {}",
                    got, expected
                );
            }
        }};
    }

    struct TestHandler;

    /// # Safety
    /// Safe because handle_signal is async-signal safe.
    unsafe impl SignalHandler for TestHandler {
        fn handle_signal(signal: Signal) {
            if TEST_SIGNAL == signal {
                TEST_SIGNAL_COUNTER.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn scopedsignalhandler_success() {
        // Prevent other test cases from running concurrently since the signal
        // handlers are shared for the process.
        let _guard = get_mutex();

        reset_counter();
        assert_counter_eq!(0);

        assert!(has_default_signal_handler(TEST_SIGNAL.into()).unwrap());
        let handler = ScopedSignalHandler::new::<TestHandler>(&[TEST_SIGNAL]).unwrap();
        assert!(!has_default_signal_handler(TEST_SIGNAL.into()).unwrap());

        // Safe because test_handler is safe.
        unsafe { send_test_signal() };

        // Give the handler time to run in case it is on a different thread.
        for _ in 1..40 {
            if TEST_SIGNAL_COUNTER.load(Ordering::SeqCst) > 0 {
                break;
            }
            sleep(Duration::from_millis(250));
        }

        assert_counter_eq!(1);

        drop(handler);
        assert!(has_default_signal_handler(TEST_SIGNAL.into()).unwrap());
    }

    #[test]
    fn scopedsignalhandler_handleralreadyset() {
        // Prevent other test cases from running concurrently since the signal
        // handlers are shared for the process.
        let _guard = get_mutex();

        reset_counter();
        assert_counter_eq!(0);

        assert!(has_default_signal_handler(TEST_SIGNAL.into()).unwrap());
        // Safe because TestHandler is async-signal safe.
        let handler = ScopedSignalHandler::new::<TestHandler>(&[TEST_SIGNAL]).unwrap();
        assert!(!has_default_signal_handler(TEST_SIGNAL.into()).unwrap());

        // Safe because TestHandler is async-signal safe.
        assert!(matches!(
            ScopedSignalHandler::new::<TestHandler>(&TEST_SIGNALS),
            Err(Error::HandlerAlreadySet(Signal::User1))
        ));

        assert_counter_eq!(0);
        drop(handler);
        assert!(has_default_signal_handler(TEST_SIGNAL.into()).unwrap());
    }

    /// Stores the thread used by WaitForInterruptHandler.
    static WAIT_FOR_INTERRUPT_THREAD_ID: AtomicI32 = AtomicI32::new(0);
    /// Forwards SIGINT to the appropriate thread.
    struct WaitForInterruptHandler;

    /// # Safety
    /// Safe because handle_signal is async-signal safe.
    unsafe impl SignalHandler for WaitForInterruptHandler {
        fn handle_signal(_: Signal) {
            let tid = WAIT_FOR_INTERRUPT_THREAD_ID.load(Ordering::SeqCst);
            // If the thread ID is set and executed on the wrong thread, forward the signal.
            if tid != 0 && gettid() != tid {
                // Safe because the handler is safe and the target thread id is expecting the signal.
                unsafe { kill(tid, Signal::Interrupt.into()) }.unwrap();
            }
        }
    }

    /// Query /proc/${tid}/status for its State and check if it is either S (sleeping) or in
    /// D (disk sleep).
    fn thread_is_sleeping(tid: Pid) -> result::Result<bool, errno::Error> {
        const PREFIX: &str = "State:";
        let mut status_reader = BufReader::new(File::open(format!("/proc/{}/status", tid))?);
        let mut line = String::new();
        loop {
            let count = status_reader.read_line(&mut line)?;
            if count == 0 {
                return Err(errno::Error::new(libc::EIO));
            }
            if line.starts_with(PREFIX) {
                return Ok(matches!(
                    line[PREFIX.len()..].trim_start().chars().next(),
                    Some('S') | Some('D')
                ));
            }
            line.clear();
        }
    }

    /// Wait for a process to block either in a sleeping or disk sleep state.
    fn wait_for_thread_to_sleep(tid: Pid, timeout: Duration) -> result::Result<(), errno::Error> {
        let start = Instant::now();
        loop {
            if thread_is_sleeping(tid)? {
                return Ok(());
            }
            if start.elapsed() > timeout {
                return Err(errno::Error::new(libc::EAGAIN));
            }
            sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn waitforinterrupt_success() {
        // Prevent other test cases from running concurrently since the signal
        // handlers are shared for the process.
        let _guard = get_mutex();

        let to_restore = get_sigaction(Signal::Interrupt).unwrap();
        clear_signal_handler(Signal::Interrupt.into()).unwrap();
        // Safe because TestHandler is async-signal safe.
        let handler =
            ScopedSignalHandler::new::<WaitForInterruptHandler>(&[Signal::Interrupt]).unwrap();

        let tid = gettid();
        WAIT_FOR_INTERRUPT_THREAD_ID.store(tid, Ordering::SeqCst);

        let join_handle = spawn(move || -> result::Result<(), errno::Error> {
            // Wait unitl the thread is ready to receive the signal.
            wait_for_thread_to_sleep(tid, Duration::from_secs(10)).unwrap();

            // Safe because the SIGINT handler is safe.
            unsafe { kill(tid, Signal::Interrupt.into()) }
        });
        let wait_ret = wait_for_interrupt();
        let join_ret = join_handle.join();

        drop(handler);
        // Safe because we are restoring the previous SIGINT handler.
        unsafe { restore_sigaction(Signal::Interrupt, to_restore) }.unwrap();

        wait_ret.unwrap();
        join_ret.unwrap().unwrap();
    }
}
