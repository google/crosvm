// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macro and helper trait for handling interrupted routines.

use std::io;

use libc::EINTR;

/// Trait for determining if a result indicates the operation was interrupted.
pub trait InterruptibleResult {
    /// Returns `true` if this result indicates the operation was interrupted and should be retried,
    /// and `false` in all other cases.
    fn is_interrupted(&self) -> bool;
}

impl<T> InterruptibleResult for crate::Result<T> {
    fn is_interrupted(&self) -> bool {
        match self {
            Err(e) if e.errno() == EINTR => true,
            _ => false,
        }
    }
}

impl<T> InterruptibleResult for io::Result<T> {
    fn is_interrupted(&self) -> bool {
        match self {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => true,
            _ => false,
        }
    }
}

/// Macro that retries the given expression every time its result indicates it was interrupted (i.e.
/// returned `EINTR`). This is useful for operations that are prone to being interrupted by
/// signals, such as blocking syscalls.
///
/// The given expression `$x` can return
///
/// * `sys_util::Result` in which case the expression is retried if the `Error::errno()` is `EINTR`.
/// * `std::io::Result` in which case the expression is retried if the `ErrorKind` is `ErrorKind::Interrupted`.
///
/// Note that if expression returns i32 (i.e. either -1 or error code), then handle_eintr_errno()
/// or handle_eintr_rc() should be used instead.
///
/// In all cases where the result does not indicate that the expression was interrupted, the result
/// is returned verbatim to the caller of this macro.
///
/// See the section titled _Interruption of system calls and library functions by signal handlers_
/// on the man page for `signal(7)` to see more information about interruptible syscalls.
///
/// To summarize, routines that use one of these syscalls _might_ need to handle `EINTR`:
///
/// * `accept(2)`
/// * `clock_nanosleep(2)`
/// * `connect(2)`
/// * `epoll_pwait(2)`
/// * `epoll_wait(2)`
/// * `fcntl(2)`
/// * `fifo(7)`
/// * `flock(2)`
/// * `futex(2)`
/// * `getrandom(2)`
/// * `inotify(7)`
/// * `io_getevents(2)`
/// * `ioctl(2)`
/// * `mq_receive(3)`
/// * `mq_send(3)`
/// * `mq_timedreceive(3)`
/// * `mq_timedsend(3)`
/// * `msgrcv(2)`
/// * `msgsnd(2)`
/// * `nanosleep(2)`
/// * `open(2)`
/// * `pause(2)`
/// * `poll(2)`
/// * `ppoll(2)`
/// * `pselect(2)`
/// * `pthread_cond_wait(3)`
/// * `pthread_mutex_lock(3)`
/// * `read(2)`
/// * `readv(2)`
/// * `recv(2)`
/// * `recvfrom(2)`
/// * `recvmmsg(2)`
/// * `recvmsg(2)`
/// * `select(2)`
/// * `sem_timedwait(3)`
/// * `sem_wait(3)`
/// * `semop(2)`
/// * `semtimedop(2)`
/// * `send(2)`
/// * `sendmsg(2)`
/// * `sendto(2)`
/// * `setsockopt(2)`
/// * `sigsuspend(2)`
/// * `sigtimedwait(2)`
/// * `sigwaitinfo(2)`
/// * `sleep(3)`
/// * `usleep(3)`
/// * `wait(2)`
/// * `wait3(2)`
/// * `wait4(2)`
/// * `waitid(2)`
/// * `waitpid(2)`
/// * `write(2)`
/// * `writev(2)`
///
/// # Examples
///
/// ```
/// # use sys_util::handle_eintr;
/// # use std::io::stdin;
/// # fn main() {
/// let mut line = String::new();
/// let res = handle_eintr!(stdin().read_line(&mut line));
/// # }
/// ```
#[macro_export]
macro_rules! handle_eintr {
    ($x:expr) => {{
        use $crate::handle_eintr::InterruptibleResult;
        let res;
        loop {
            match $x {
                ref v if v.is_interrupted() => continue,
                v => {
                    res = v;
                    break;
                }
            }
        }
        res
    }};
}

/// Macro that retries the given expression every time its result indicates it was interrupted.
/// It is intended to use with system functions that return `EINTR` and other error codes
/// directly as their result.
/// Most of reentrant functions use this way of signalling errors.
#[macro_export]
macro_rules! handle_eintr_rc {
    ($x:expr) => {{
        use libc::EINTR;
        let mut res;
        loop {
            res = $x;
            if res != EINTR {
                break;
            }
        }
        res
    }};
}

/// Macro that retries the given expression every time its result indicates it was interrupted.
/// It is intended to use with system functions that signal error by returning `-1` and setting
/// `errno` to appropriate error code (`EINTR`, `EINVAL`, etc.)
/// Most of standard non-reentrant libc functions use this way of signalling errors.
#[macro_export]
macro_rules! handle_eintr_errno {
    ($x:expr) => {{
        use libc::EINTR;
        use $crate::Error;
        let mut res;
        loop {
            res = $x;
            if res != -1 || Error::last() != Error::new(EINTR) {
                break;
            }
        }
        res
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::set_errno;
    use crate::Error as SysError;

    #[test]
    fn i32_eintr_rc() {
        let mut count = 3;
        let mut dummy = || {
            count -= 1;
            if count > 0 {
                EINTR
            } else {
                0
            }
        };
        let res = handle_eintr_rc!(dummy());
        assert_eq!(res, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn i32_eintr_errno() {
        let mut count = 3;
        let mut dummy = || {
            count -= 1;
            if count > 0 {
                set_errno(EINTR);
                -1
            } else {
                56
            }
        };
        let res = handle_eintr_errno!(dummy());
        assert_eq!(res, 56);
        assert_eq!(count, 0);
    }

    #[test]
    fn sys_eintr() {
        let mut count = 7;
        let mut dummy = || {
            count -= 1;
            if count > 1 {
                Err(SysError::new(EINTR))
            } else {
                Ok(101)
            }
        };
        let res = handle_eintr!(dummy());
        assert_eq!(res, Ok(101));
        assert_eq!(count, 1);
    }

    #[test]
    fn io_eintr() {
        let mut count = 108;
        let mut dummy = || {
            count -= 1;
            if count > 99 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted again :(",
                ))
            } else {
                Ok(32)
            }
        };
        let res = handle_eintr!(dummy());
        assert_eq!(res.unwrap(), 32);
        assert_eq!(count, 99);
    }
}
