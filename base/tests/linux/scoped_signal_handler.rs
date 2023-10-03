// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::Once;
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;
use std::time::Instant;

use base::platform::gettid;
use base::platform::kill;
use base::platform::scoped_signal_handler::Error;
use base::platform::scoped_signal_handler::Result;
use base::platform::Error as ErrnoError;
use base::sys::clear_signal_handler;
use base::sys::has_default_signal_handler;
use base::sys::wait_for_interrupt;
use base::sys::ScopedSignalHandler;
use base::sys::Signal;
use base::sys::SignalHandler;
use base::Pid;
use libc::sigaction;

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
        Err(Error::Sigaction(signal, ErrnoError::last()))
    } else {
        Ok(sigact)
    }
}

/// Safety:
/// This is only safe if the signal handler set in sigaction is safe.
unsafe fn restore_sigaction(signal: Signal, sigact: sigaction) -> Result<sigaction> {
    if sigaction(signal.into(), &sigact, null_mut()) < 0 {
        Err(Error::Sigaction(signal, ErrnoError::last()))
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
        ScopedSignalHandler::new::<TestHandler>(TEST_SIGNALS),
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
fn thread_is_sleeping(tid: Pid) -> std::result::Result<bool, ErrnoError> {
    const PREFIX: &str = "State:";
    let mut status_reader = BufReader::new(File::open(format!("/proc/{}/status", tid))?);
    let mut line = String::new();
    loop {
        let count = status_reader.read_line(&mut line)?;
        if count == 0 {
            return Err(ErrnoError::new(libc::EIO));
        }
        if let Some(stripped) = line.strip_prefix(PREFIX) {
            return Ok(matches!(
                stripped.trim_start().chars().next(),
                Some('S') | Some('D')
            ));
        }
        line.clear();
    }
}

/// Wait for a process to block either in a sleeping or disk sleep state.
fn wait_for_thread_to_sleep(tid: Pid, timeout: Duration) -> std::result::Result<(), ErrnoError> {
    let start = Instant::now();
    loop {
        if thread_is_sleeping(tid)? {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(ErrnoError::new(libc::EAGAIN));
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

    let join_handle = spawn(move || -> std::result::Result<(), ErrnoError> {
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
