// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;
use std::ptr::null;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};

use libc::{c_int, c_long, timespec, time_t, nfds_t, sigset_t, pollfd, syscall, SYS_ppoll, POLLIN};

use {Result, errno_result};

// The libc wrapper suppresses the kernel's changes to timeout, so we use the syscall directly.
unsafe fn ppoll(fds: *mut pollfd,
                nfds: nfds_t,
                timeout: *mut timespec,
                sigmask: *const sigset_t,
                sigsetsize: usize)
                -> c_int {
    syscall(SYS_ppoll, fds, nfds, timeout, sigmask, sigsetsize) as c_int
}

/// Trait for file descriptors that can be polled for input.
///
/// This is marked unsafe because the implementation must promise that the returned RawFd is valid
/// for polling purposes and that the lifetime of the returned fd is at least that of the trait
/// object.
pub unsafe trait Pollable {
    /// Gets the file descriptor that can be polled for input.
    fn pollable_fd(&self) -> RawFd;
}

unsafe impl Pollable for UnixStream {
    fn pollable_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

unsafe impl Pollable for UnixDatagram {
    fn pollable_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

/// Used to poll multiple `Pollable` objects at once.
///
/// # Example
///
/// ```
/// # use sys_util::{Result, EventFd, Poller, Pollable};
/// # fn test() -> Result<()> {
///     let evt1 = EventFd::new()?;
///     let evt2 = EventFd::new()?;
///     evt2.write(1)?;
///
///     let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];
///
///     let mut poller = Poller::new(2);
///     assert_eq!(poller.poll(&pollables[..]), Ok([2].as_ref()));
/// #   Ok(())
/// # }
/// ```
pub struct Poller {
    pollfds: Vec<pollfd>,
    tokens: Vec<u32>,
}

impl Poller {
    /// Constructs a new poller object with the given `capacity` of Pollable objects pre-allocated.
    pub fn new(capacity: usize) -> Poller {
        Poller {
            pollfds: Vec::with_capacity(capacity),
            tokens: Vec::with_capacity(capacity),
        }
    }

    /// Waits for any of the given slice of `token`-`Pollable` tuples to be readable without
    /// blocking and returns the `token` of each that is readable.
    ///
    /// This is guaranteed to not allocate if `pollables.len()` is less than the `capacity` given in
    /// `Poller::new`.
    pub fn poll(&mut self, pollables: &[(u32, &Pollable)]) -> Result<&[u32]> {
        self.poll_timeout(pollables, &mut Duration::new(time_t::max_value() as u64, 0))
    }

    /// Waits for up to the given timeout for any of the given slice of `token`-`Pollable` tuples to
    /// be readable without blocking and returns the `token` of each that is readable.
    ///
    /// If a timeout duration is given, the duration will be modified to the unused portion of the
    /// timeout, even if an error is returned.
    ///
    /// This is guaranteed to not allocate if `pollables.len()` is less than the `capacity` given in
    /// `Poller::new`.
    pub fn poll_timeout(&mut self,
                        pollables: &[(u32, &Pollable)],
                        timeout: &mut Duration)
                        -> Result<&[u32]> {
        self.pollfds.clear();
        for pollable in pollables.iter() {
            self.pollfds
                .push(pollfd {
                          fd: pollable.1.pollable_fd(),
                          events: POLLIN,
                          revents: 0,
                      });
        }

        let mut timeout_spec = timespec {
            tv_sec: timeout.as_secs() as time_t,
            tv_nsec: timeout.subsec_nanos() as c_long,
        };
        // Safe because poll is given the correct length of properly initialized pollfds, and we
        // check the return result.
        let ret = unsafe {
            handle_eintr_errno!(ppoll(self.pollfds.as_mut_ptr(),
                                      self.pollfds.len() as nfds_t,
                                      &mut timeout_spec,
                                      null(),
                                      0))
        };

        *timeout = Duration::new(timeout_spec.tv_sec as u64, timeout_spec.tv_nsec as u32);

        if ret < 0 {
            return errno_result();
        }

        self.tokens.clear();
        for (pollfd, pollable) in self.pollfds.iter().zip(pollables.iter()) {
            if (pollfd.revents & POLLIN) != 0 {
                self.tokens.push(pollable.0);
            }
        }

        Ok(&self.tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use EventFd;

    #[test]
    fn poller() {
        let evt1 = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();
        evt2.write(1).unwrap();

        let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];

        let mut poller = Poller::new(2);
        assert_eq!(poller.poll(&pollables[..]), Ok([2].as_ref()));
    }

    #[test]
    fn poller_multi() {
        let evt1 = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();

        let pollables: Vec<(u32, &Pollable)> = vec![(1, &evt1), (2, &evt2)];

        let mut poller = Poller::new(2);
        assert_eq!(poller.poll(&pollables[..]), Ok([1, 2].as_ref()));
    }

    #[test]
    fn timeout() {
        let evt1 = EventFd::new().unwrap();
        let initial_dur = Duration::from_millis(10);
        let mut timeout_dur = initial_dur;
        let mut poller = Poller::new(0);
        assert_eq!(poller.poll_timeout(&[(1, &evt1)], &mut timeout_dur),
                   Ok([].as_ref()));
        assert_eq!(timeout_dur, Duration::from_secs(0));
        evt1.write(1).unwrap();
        timeout_dur = initial_dur;
        assert_eq!(poller.poll_timeout(&[(1, &evt1)], &mut timeout_dur),
                   Ok([1].as_ref()));
        assert!(timeout_dur < initial_dur);
    }
}
