// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::File;
use std::mem;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::result;

use libc::{c_void, read, signalfd, signalfd_siginfo};
use libc::{EAGAIN, SFD_CLOEXEC, SFD_NONBLOCK};

use crate::errno;
use crate::signal;

#[derive(Debug)]
pub enum Error {
    /// Failed to construct sigset when creating signalfd.
    CreateSigset(errno::Error),
    /// Failed to create a new signalfd.
    CreateSignalFd(errno::Error),
    /// Failed to block the signal when creating signalfd.
    CreateBlockSignal(signal::Error),
    /// Unable to read from signalfd.
    SignalFdRead(errno::Error),
    /// Signalfd could be read, but didn't return a full siginfo struct.
    /// This wraps the number of bytes that were actually read.
    SignalFdPartialRead(usize),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CreateSigset(e) => write!(
                f,
                "failed to construct sigset when creating signalfd: {}",
                e,
            ),
            CreateSignalFd(e) => write!(f, "failed to create a new signalfd: {}", e),
            CreateBlockSignal(e) => write!(
                f,
                "failed to block the signal when creating signalfd: {}",
                e,
            ),
            SignalFdRead(e) => write!(f, "unable to read from signalfd: {}", e),
            SignalFdPartialRead(read) => write!(
                f,
                "signalfd failed to return a full siginfo struct, read only {} bytes",
                read,
            ),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// A safe wrapper around a Linux signalfd (man 2 signalfd).
///
/// A signalfd can be used for non-synchronous signals (such as SIGCHLD) so that
/// signals can be processed without the use of a signal handler.
pub struct SignalFd {
    signalfd: File,
    signal: c_int,
}

impl SignalFd {
    /// Creates a new SignalFd for the given signal, blocking the normal handler
    /// for the signal as well. Since we mask out the normal handler, this is
    /// a risky operation - signal masking will persist across fork and even
    /// **exec** so the user of SignalFd should think long and hard about
    /// when to mask signals.
    pub fn new(signal: c_int) -> Result<SignalFd> {
        let sigset = signal::create_sigset(&[signal]).map_err(Error::CreateSigset)?;

        // This is safe as we check the return value and know that fd is valid.
        let fd = unsafe { signalfd(-1, &sigset, SFD_CLOEXEC | SFD_NONBLOCK) };
        if fd < 0 {
            return Err(Error::CreateSignalFd(errno::Error::last()));
        }

        // Mask out the normal handler for the signal.
        signal::block_signal(signal).map_err(Error::CreateBlockSignal)?;

        // This is safe because we checked fd for success and know the
        // kernel gave us an fd that we own.
        unsafe {
            Ok(SignalFd {
                signalfd: File::from_raw_fd(fd),
                signal,
            })
        }
    }

    /// Read a siginfo struct from the signalfd, if available.
    pub fn read(&self) -> Result<Option<signalfd_siginfo>> {
        // signalfd_siginfo doesn't have a default, so just zero it.
        let mut siginfo: signalfd_siginfo = unsafe { mem::zeroed() };
        let siginfo_size = mem::size_of::<signalfd_siginfo>();

        // This read is safe since we've got the space allocated for a
        // single signalfd_siginfo, and that's exactly how much we're
        // reading. Handling of EINTR is not required since SFD_NONBLOCK
        // was specified. signalfds will always read in increments of
        // sizeof(signalfd_siginfo); see man 2 signalfd.
        let ret = unsafe {
            read(
                self.signalfd.as_raw_fd(),
                &mut siginfo as *mut signalfd_siginfo as *mut c_void,
                siginfo_size,
            )
        };

        if ret < 0 {
            let err = errno::Error::last();
            if err.errno() == EAGAIN {
                Ok(None)
            } else {
                Err(Error::SignalFdRead(err))
            }
        } else if ret == (siginfo_size as isize) {
            Ok(Some(siginfo))
        } else {
            Err(Error::SignalFdPartialRead(ret as usize))
        }
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.signalfd.as_raw_fd()
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        // This is thread-safe and safe in the sense that we're doing what
        // was promised - unmasking the signal when we go out of scope.
        let res = signal::unblock_signal(self.signal);
        if let Err(e) = res {
            error!("signalfd failed to unblock signal {}: {}", self.signal, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::signal::SIGRTMIN;
    use libc::{pthread_sigmask, raise, sigismember, sigset_t};
    use std::mem;
    use std::ptr::null;

    #[test]
    fn new() {
        SignalFd::new(SIGRTMIN()).unwrap();
    }

    #[test]
    fn read() {
        let sigid = SIGRTMIN() + 1;
        let sigrt_fd = SignalFd::new(sigid).unwrap();

        let ret = unsafe { raise(sigid) };
        assert_eq!(ret, 0);

        let siginfo = sigrt_fd.read().unwrap().unwrap();
        assert_eq!(siginfo.ssi_signo, sigid as u32);
    }

    #[test]
    fn drop() {
        let sigid = SIGRTMIN() + 2;

        let sigrt_fd = SignalFd::new(sigid).unwrap();
        unsafe {
            let mut sigset: sigset_t = mem::zeroed();
            pthread_sigmask(0, null(), &mut sigset as *mut sigset_t);
            assert_eq!(sigismember(&sigset, sigid), 1);
        }

        mem::drop(sigrt_fd);

        // The signal should no longer be masked.
        unsafe {
            let mut sigset: sigset_t = mem::zeroed();
            pthread_sigmask(0, null(), &mut sigset as *mut sigset_t);
            assert_eq!(sigismember(&sigset, sigid), 0);
        }
    }
}
