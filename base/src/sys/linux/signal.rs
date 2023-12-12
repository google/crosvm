// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::io;
use std::mem;
use std::os::unix::thread::JoinHandleExt;
use std::ptr::null;
use std::ptr::null_mut;
use std::result;
use std::thread::JoinHandle;
use std::time::Duration;

use libc::c_int;
use libc::pthread_kill;
use libc::pthread_sigmask;
use libc::pthread_t;
use libc::sigaction;
use libc::sigaddset;
use libc::sigemptyset;
use libc::siginfo_t;
use libc::sigismember;
use libc::sigpending;
use libc::sigset_t;
use libc::sigtimedwait;
use libc::sigwait;
use libc::timespec;
use libc::EAGAIN;
use libc::EINTR;
use libc::EINVAL;
use libc::SA_RESTART;
use libc::SIG_BLOCK;
use libc::SIG_DFL;
use libc::SIG_UNBLOCK;
use remain::sorted;
use thiserror::Error;

use super::duration_to_timespec;
use super::errno_result;
use super::Error as ErrnoError;
use super::Pid;
use super::Result;
use crate::handle_eintr_errno;
use crate::handle_eintr_rc;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// The signal could not be blocked.
    #[error("signal could not be blocked: {0}")]
    BlockSignal(ErrnoError),
    /// Failed to check if given signal is in the set of pending signals.
    #[error("failed to check whether given signal is in the pending set: {0}")]
    ClearCheckPending(ErrnoError),
    /// Failed to get pending signals.
    #[error("failed to get pending signals: {0}")]
    ClearGetPending(ErrnoError),
    /// Failed to wait for given signal.
    #[error("failed to wait for given signal: {0}")]
    ClearWaitPending(ErrnoError),
    /// Failed to check if the requested signal is in the blocked set already.
    #[error("failed to check whether requested signal is in the blocked set: {0}")]
    CompareBlockedSignals(ErrnoError),
    /// Couldn't create a sigset.
    #[error("couldn't create a sigset: {0}")]
    CreateSigset(ErrnoError),
    /// Failed to get session id.
    #[error("failed to get session id: {0}")]
    GetSid(ErrnoError),
    /// Failed to send signal to pid.
    #[error("failed to send signal: {0}")]
    Kill(ErrnoError),
    /// The signal mask could not be retrieved.
    #[error("failed to retrieve signal mask: {}", io::Error::from_raw_os_error(*.0))]
    RetrieveSignalMask(i32),
    /// Converted signum greater than SIGRTMAX.
    #[error("got RT signal greater than max: {0:?}")]
    RtSignumGreaterThanMax(Signal),
    /// The wrapped signal has already been blocked.
    #[error("signal {0} already blocked")]
    SignalAlreadyBlocked(c_int),
    /// Timeout reached.
    #[error("timeout reached.")]
    TimedOut,
    /// The signal could not be unblocked.
    #[error("signal could not be unblocked: {0}")]
    UnblockSignal(ErrnoError),
    /// Failed to convert signum to Signal.
    #[error("unrecoginized signal number: {0}")]
    UnrecognizedSignum(i32),
    /// Failed to wait for signal.
    #[error("failed to wait for signal: {0}")]
    WaitForSignal(ErrnoError),
    /// Failed to wait for pid.
    #[error("failed to wait for process: {0}")]
    WaitPid(ErrnoError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Signal {
    Abort = libc::SIGABRT,
    Alarm = libc::SIGALRM,
    Bus = libc::SIGBUS,
    Child = libc::SIGCHLD,
    Continue = libc::SIGCONT,
    ExceededFileSize = libc::SIGXFSZ,
    FloatingPointException = libc::SIGFPE,
    HangUp = libc::SIGHUP,
    IllegalInstruction = libc::SIGILL,
    Interrupt = libc::SIGINT,
    Io = libc::SIGIO,
    Kill = libc::SIGKILL,
    Pipe = libc::SIGPIPE,
    Power = libc::SIGPWR,
    Profile = libc::SIGPROF,
    Quit = libc::SIGQUIT,
    SegmentationViolation = libc::SIGSEGV,
    StackFault = libc::SIGSTKFLT,
    Stop = libc::SIGSTOP,
    Sys = libc::SIGSYS,
    Trap = libc::SIGTRAP,
    Terminate = libc::SIGTERM,
    TtyIn = libc::SIGTTIN,
    TtyOut = libc::SIGTTOU,
    TtyStop = libc::SIGTSTP,
    Urgent = libc::SIGURG,
    User1 = libc::SIGUSR1,
    User2 = libc::SIGUSR2,
    VtAlarm = libc::SIGVTALRM,
    Winch = libc::SIGWINCH,
    Xcpu = libc::SIGXCPU,
    // Rt signal numbers are be adjusted in the conversion to integer.
    Rt0 = libc::SIGSYS + 1,
    Rt1,
    Rt2,
    Rt3,
    Rt4,
    Rt5,
    Rt6,
    Rt7,
    // Only 8 are guaranteed by POSIX, Linux has 32, but only 29 or 30 are usable.
    Rt8,
    Rt9,
    Rt10,
    Rt11,
    Rt12,
    Rt13,
    Rt14,
    Rt15,
    Rt16,
    Rt17,
    Rt18,
    Rt19,
    Rt20,
    Rt21,
    Rt22,
    Rt23,
    Rt24,
    Rt25,
    Rt26,
    Rt27,
    Rt28,
    Rt29,
    Rt30,
    Rt31,
}

impl From<Signal> for c_int {
    fn from(signal: Signal) -> c_int {
        let num = signal as libc::c_int;
        if num >= Signal::Rt0 as libc::c_int {
            return num - (Signal::Rt0 as libc::c_int) + SIGRTMIN();
        }
        num
    }
}

impl TryFrom<c_int> for Signal {
    type Error = Error;

    fn try_from(value: c_int) -> result::Result<Self, Self::Error> {
        use Signal::*;

        Ok(match value {
            libc::SIGABRT => Abort,
            libc::SIGALRM => Alarm,
            libc::SIGBUS => Bus,
            libc::SIGCHLD => Child,
            libc::SIGCONT => Continue,
            libc::SIGXFSZ => ExceededFileSize,
            libc::SIGFPE => FloatingPointException,
            libc::SIGHUP => HangUp,
            libc::SIGILL => IllegalInstruction,
            libc::SIGINT => Interrupt,
            libc::SIGIO => Io,
            libc::SIGKILL => Kill,
            libc::SIGPIPE => Pipe,
            libc::SIGPWR => Power,
            libc::SIGPROF => Profile,
            libc::SIGQUIT => Quit,
            libc::SIGSEGV => SegmentationViolation,
            libc::SIGSTKFLT => StackFault,
            libc::SIGSTOP => Stop,
            libc::SIGSYS => Sys,
            libc::SIGTRAP => Trap,
            libc::SIGTERM => Terminate,
            libc::SIGTTIN => TtyIn,
            libc::SIGTTOU => TtyOut,
            libc::SIGTSTP => TtyStop,
            libc::SIGURG => Urgent,
            libc::SIGUSR1 => User1,
            libc::SIGUSR2 => User2,
            libc::SIGVTALRM => VtAlarm,
            libc::SIGWINCH => Winch,
            libc::SIGXCPU => Xcpu,
            _ => {
                if value < SIGRTMIN() {
                    return Err(Error::UnrecognizedSignum(value));
                }
                let signal = match value - SIGRTMIN() {
                    0 => Rt0,
                    1 => Rt1,
                    2 => Rt2,
                    3 => Rt3,
                    4 => Rt4,
                    5 => Rt5,
                    6 => Rt6,
                    7 => Rt7,
                    8 => Rt8,
                    9 => Rt9,
                    10 => Rt10,
                    11 => Rt11,
                    12 => Rt12,
                    13 => Rt13,
                    14 => Rt14,
                    15 => Rt15,
                    16 => Rt16,
                    17 => Rt17,
                    18 => Rt18,
                    19 => Rt19,
                    20 => Rt20,
                    21 => Rt21,
                    22 => Rt22,
                    23 => Rt23,
                    24 => Rt24,
                    25 => Rt25,
                    26 => Rt26,
                    27 => Rt27,
                    28 => Rt28,
                    29 => Rt29,
                    30 => Rt30,
                    31 => Rt31,
                    _ => {
                        return Err(Error::UnrecognizedSignum(value));
                    }
                };
                if value > SIGRTMAX() {
                    return Err(Error::RtSignumGreaterThanMax(signal));
                }
                signal
            }
        })
    }
}

pub type SignalResult<T> = result::Result<T, Error>;

#[link(name = "c")]
extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

/// Returns the minimum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMIN() -> c_int {
    // SAFETY: trivially safe
    unsafe { __libc_current_sigrtmin() }
}

/// Returns the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMAX() -> c_int {
    // SAFETY: trivially safe
    unsafe { __libc_current_sigrtmax() }
}

fn valid_rt_signal_num(num: c_int) -> bool {
    num >= SIGRTMIN() && num <= SIGRTMAX()
}

/// Registers `handler` as the signal handler of signum `num`.
///
/// # Safety
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_signal_handler(num: c_int, handler: extern "C" fn(c_int)) -> Result<()> {
    let mut sigact: sigaction = mem::zeroed();
    sigact.sa_flags = SA_RESTART;
    sigact.sa_sigaction = handler as *const () as usize;

    let ret = sigaction(num, &sigact, null_mut());
    if ret < 0 {
        return errno_result();
    }

    Ok(())
}

/// Resets the signal handler of signum `num` back to the default.
pub fn clear_signal_handler(num: c_int) -> Result<()> {
    // SAFETY:
    // Safe because sigaction is owned and expected to be initialized ot zeros.
    let mut sigact: sigaction = unsafe { mem::zeroed() };
    sigact.sa_flags = SA_RESTART;
    sigact.sa_sigaction = SIG_DFL;

    // SAFETY:
    // Safe because sigact is owned, and this is restoring the default signal handler.
    let ret = unsafe { sigaction(num, &sigact, null_mut()) };
    if ret < 0 {
        return errno_result();
    }

    Ok(())
}

/// Registers `handler` as the signal handler for the real-time signal with signum `num`.
///
/// The value of `num` must be within [`SIGRTMIN`, `SIGRTMAX`] range.
///
/// # Safety
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_rt_signal_handler(num: c_int, handler: extern "C" fn(c_int)) -> Result<()> {
    if !valid_rt_signal_num(num) {
        return Err(ErrnoError::new(EINVAL));
    }

    register_signal_handler(num, handler)
}

/// Creates `sigset` from an array of signal numbers.
///
/// This is a helper function used when we want to manipulate signals.
pub fn create_sigset(signals: &[c_int]) -> Result<sigset_t> {
    // SAFETY:
    // sigset will actually be initialized by sigemptyset below.
    let mut sigset: sigset_t = unsafe { mem::zeroed() };

    // SAFETY:
    // Safe - return value is checked.
    let ret = unsafe { sigemptyset(&mut sigset) };
    if ret < 0 {
        return errno_result();
    }

    for signal in signals {
        // SAFETY:
        // Safe - return value is checked.
        let ret = unsafe { sigaddset(&mut sigset, *signal) };
        if ret < 0 {
            return errno_result();
        }
    }

    Ok(sigset)
}

/// Wait for signal before continuing. The signal number of the consumed signal is returned on
/// success. EAGAIN means the timeout was reached.
pub fn wait_for_signal(signals: &[c_int], timeout: Option<Duration>) -> Result<c_int> {
    let sigset = create_sigset(signals)?;

    match timeout {
        Some(timeout) => {
            let ts = duration_to_timespec(timeout);
            // SAFETY:
            // Safe - return value is checked.
            let ret = handle_eintr_errno!(unsafe { sigtimedwait(&sigset, null_mut(), &ts) });
            if ret < 0 {
                errno_result()
            } else {
                Ok(ret)
            }
        }
        None => {
            let mut ret: c_int = 0;
            // SAFETY: Safe because args are valid and the return value is checked.
            let err = handle_eintr_rc!(unsafe { sigwait(&sigset, &mut ret as *mut c_int) });
            if err != 0 {
                Err(ErrnoError::new(err))
            } else {
                Ok(ret)
            }
        }
    }
}

/// Retrieves the signal mask of the current thread as a vector of c_ints.
pub fn get_blocked_signals() -> SignalResult<Vec<c_int>> {
    let mut mask = Vec::new();

    // SAFETY:
    // Safe - return values are checked.
    unsafe {
        let mut old_sigset: sigset_t = mem::zeroed();
        let ret = pthread_sigmask(SIG_BLOCK, null(), &mut old_sigset as *mut sigset_t);
        if ret < 0 {
            return Err(Error::RetrieveSignalMask(ret));
        }

        for num in 0..=SIGRTMAX() {
            if sigismember(&old_sigset, num) > 0 {
                mask.push(num);
            }
        }
    }

    Ok(mask)
}

/// Masks given signal.
///
/// If signal is already blocked the call will fail with Error::SignalAlreadyBlocked
/// result.
pub fn block_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // SAFETY:
    // Safe - return values are checked.
    unsafe {
        let mut old_sigset: sigset_t = mem::zeroed();
        let ret = pthread_sigmask(SIG_BLOCK, &sigset, &mut old_sigset as *mut sigset_t);
        if ret < 0 {
            return Err(Error::BlockSignal(ErrnoError::last()));
        }
        let ret = sigismember(&old_sigset, num);
        match ret.cmp(&0) {
            Ordering::Less => {
                return Err(Error::CompareBlockedSignals(ErrnoError::last()));
            }
            Ordering::Greater => {
                return Err(Error::SignalAlreadyBlocked(num));
            }
            _ => (),
        };
    }
    Ok(())
}

/// Unmasks given signal.
pub fn unblock_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // SAFETY:
    // Safe - return value is checked.
    let ret = unsafe { pthread_sigmask(SIG_UNBLOCK, &sigset, null_mut()) };
    if ret < 0 {
        return Err(Error::UnblockSignal(ErrnoError::last()));
    }
    Ok(())
}

/// Clears pending signal.
pub fn clear_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    while {
        // SAFETY:
        // This is safe as we are rigorously checking return values
        // of libc calls.
        unsafe {
            let mut siginfo: siginfo_t = mem::zeroed();
            let ts = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // Attempt to consume one instance of pending signal. If signal
            // is not pending, the call will fail with EAGAIN or EINTR.
            let ret = sigtimedwait(&sigset, &mut siginfo, &ts);
            if ret < 0 {
                let e = ErrnoError::last();
                match e.errno() {
                    EAGAIN | EINTR => {}
                    _ => {
                        return Err(Error::ClearWaitPending(ErrnoError::last()));
                    }
                }
            }

            // This sigset will be actually filled with `sigpending` call.
            let mut chkset: sigset_t = mem::zeroed();
            // See if more instances of the signal are pending.
            let ret = sigpending(&mut chkset);
            if ret < 0 {
                return Err(Error::ClearGetPending(ErrnoError::last()));
            }

            let ret = sigismember(&chkset, num);
            if ret < 0 {
                return Err(Error::ClearCheckPending(ErrnoError::last()));
            }

            // This is do-while loop condition.
            ret != 0
        }
    } {}

    Ok(())
}

/// # Safety
/// This is marked unsafe because it allows signals to be sent to arbitrary PIDs. Sending some
/// signals may lead to undefined behavior. Also, the return codes of the child processes need to be
/// reaped to avoid leaking zombie processes.
pub unsafe fn kill(pid: Pid, signum: c_int) -> Result<()> {
    let ret = libc::kill(pid, signum);

    if ret != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// Trait for threads that can be signalled via `pthread_kill`.
///
/// Note that this is only useful for signals between SIGRTMIN and SIGRTMAX because these are
/// guaranteed to not be used by the C runtime.
///
/// # Safety
/// This is marked unsafe because the implementation of this trait must guarantee that the returned
/// pthread_t is valid and has a lifetime at least that of the trait object.
pub unsafe trait Killable {
    fn pthread_handle(&self) -> pthread_t;

    /// Sends the signal `num` to this killable thread.
    ///
    /// The value of `num` must be within [`SIGRTMIN`, `SIGRTMAX`] range.
    fn kill(&self, num: c_int) -> Result<()> {
        if !valid_rt_signal_num(num) {
            return Err(ErrnoError::new(EINVAL));
        }

        // SAFETY:
        // Safe because we ensure we are using a valid pthread handle, a valid signal number, and
        // check the return result.
        let ret = unsafe { pthread_kill(self.pthread_handle(), num) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

// SAFETY:
// Safe because we fulfill our contract of returning a genuine pthread handle.
unsafe impl<T> Killable for JoinHandle<T> {
    fn pthread_handle(&self) -> pthread_t {
        self.as_pthread_t() as _
    }
}

// Represents a temporarily blocked signal. It will unblock the signal when dropped.
pub struct BlockedSignal {
    signal_num: c_int,
}

impl BlockedSignal {
    // Returns a `BlockedSignal` if the specified signal can be blocked, otherwise None.
    pub fn new(signal_num: c_int) -> Option<BlockedSignal> {
        if block_signal(signal_num).is_ok() {
            Some(BlockedSignal { signal_num })
        } else {
            None
        }
    }
}

impl Drop for BlockedSignal {
    fn drop(&mut self) {
        unblock_signal(self.signal_num).expect("failed to restore signal mask");
    }
}
