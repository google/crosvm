// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{c_int, signal,
           sigset_t, sigaddset, sigemptyset, sigismember,
           pthread_t, pthread_kill, pthread_sigmask,
           SIG_BLOCK, SIG_UNBLOCK, SIG_ERR, EINVAL};

use std::mem;
use std::ptr::null_mut;
use std::result;
use std::thread::JoinHandle;
use std::os::unix::thread::JoinHandleExt;

use {errno, errno_result};

#[derive(Debug)]
pub enum Error {
    /// Couldn't create a sigset.
    CreateSigset(errno::Error),
    /// The wrapped signal has already been blocked.
    SignalAlreadyBlocked(c_int),
    /// Failed to check if the requested signal is in the blocked set already.
    CompareBlockedSignals(errno::Error),
    /// The signal could not be blocked.
    BlockSignal(errno::Error),
    /// The signal could not be unblocked.
    UnblockSignal(errno::Error),
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
    unsafe { __libc_current_sigrtmin() }
}

/// Returns the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMAX() -> c_int {
    unsafe { __libc_current_sigrtmax() }
}

fn valid_signal_num(num: c_int) -> bool {
    num >= SIGRTMIN() && num <= SIGRTMAX()
}

/// Registers `handler` as the signal handler of signum `num`.
///
/// The value of `num` must be within [`SIGRTMIN`, `SIGRTMAX`] range.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
pub unsafe fn register_signal_handler(
    num: c_int,
    handler: extern "C" fn() -> (),
) -> errno::Result<()> {
    if !valid_signal_num(num) {
        return Err(errno::Error::new(EINVAL));
    }
    let ret = signal(num, handler as *const () as usize);
    if ret == SIG_ERR {
        return errno_result();
    }

    Ok(())
}

/// Creates `sigset` from an array of signal numbers.
///
/// This is a helper function used when we want to manipulate signals.
pub fn create_sigset(signals: &[c_int]) -> errno::Result<sigset_t> {
    // sigset will actually be initialized by sigemptyset below.
    let mut sigset: sigset_t = unsafe { mem::zeroed() };

    // Safe - return value is checked.
    let ret = unsafe { sigemptyset(&mut sigset) };
    if ret < 0 {
        return errno_result();
    }

    for signal in signals {
        // Safe - return value is checked.
        let ret = unsafe { sigaddset(&mut sigset, *signal) };
        if ret < 0 {
            return errno_result();
        }
    }

    Ok(sigset)
}

/// Masks given signal.
///
/// If signal is already blocked the call will fail with Error::SignalAlreadyBlocked
/// result.
pub fn block_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // Safe - return values are checked.
    unsafe {
        let mut old_sigset: sigset_t = mem::zeroed();
        let ret = pthread_sigmask(SIG_BLOCK, &sigset, &mut old_sigset as *mut sigset_t);
        if ret < 0 {
            return Err(Error::BlockSignal(errno::Error::last()));
        }
        let ret = sigismember(&old_sigset, num);
        if ret < 0 {
            return Err(Error::CompareBlockedSignals(errno::Error::last()));
        } else if ret > 0 {
            return Err(Error::SignalAlreadyBlocked(num));
        }
    }
    Ok(())
}

/// Unmasks given signal.
pub fn unblock_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // Safe - return value is checked.
    let ret = unsafe { pthread_sigmask(SIG_UNBLOCK, &sigset, null_mut()) };
    if ret < 0 {
        return Err(Error::UnblockSignal(errno::Error::last()));
    }
    Ok(())
}

/// Trait for threads that can be signalled via `pthread_kill`.
///
/// Note that this is only useful for signals between SIGRTMIN and SIGRTMAX because these are
/// guaranteed to not be used by the C runtime.
///
/// This is marked unsafe because the implementation of this trait must guarantee that the returned
/// pthread_t is valid and has a lifetime at least that of the trait object.
pub unsafe trait Killable {
    fn pthread_handle(&self) -> pthread_t;

    /// Sends the signal `num` to this killable thread.
    ///
    /// The value of `num` must be within [`SIGRTMIN`, `SIGRTMAX`] range.
    fn kill(&self, num: c_int) -> errno::Result<()> {
        if !valid_signal_num(num) {
            return Err(errno::Error::new(EINVAL));
        }

        // Safe because we ensure we are using a valid pthread handle, a valid signal number, and
        // check the return result.
        let ret = unsafe { pthread_kill(self.pthread_handle(), num) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

// Safe because we fulfill our contract of returning a genuine pthread handle.
unsafe impl<T> Killable for JoinHandle<T> {
    fn pthread_handle(&self) -> pthread_t {
        self.as_pthread_t()
    }
}
