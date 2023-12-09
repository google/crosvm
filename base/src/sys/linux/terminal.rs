// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Stdin;
use std::mem::zeroed;
use std::os::unix::io::RawFd;

use libc::isatty;
use libc::read;
use libc::tcgetattr;
use libc::tcsetattr;
use libc::termios;
use libc::ECHO;
use libc::ICANON;
use libc::ISIG;
use libc::O_NONBLOCK;
use libc::STDIN_FILENO;
use libc::TCSANOW;

use crate::errno::Result;
use crate::errno_result;
use crate::unix::add_fd_flags;
use crate::unix::clear_fd_flags;

fn modify_mode<F: FnOnce(&mut termios)>(fd: RawFd, f: F) -> Result<()> {
    // Safe because we check the return value of isatty.
    if unsafe { isatty(fd) } != 1 {
        return Ok(());
    }

    // The following pair are safe because termios gets totally overwritten by tcgetattr and we
    // check the return result.
    let mut termios: termios = unsafe { zeroed() };
    let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
    if ret < 0 {
        return errno_result();
    }
    let mut new_termios = termios;
    f(&mut new_termios);
    // Safe because the syscall will only read the extent of termios and we check the return result.
    let ret = unsafe { tcsetattr(fd, TCSANOW, &new_termios as *const _) };
    if ret < 0 {
        return errno_result();
    }

    Ok(())
}

/// Safe only when the FD given is valid and reading the fd will have no Rust safety implications.
unsafe fn read_raw(fd: RawFd, out: &mut [u8]) -> Result<usize> {
    let ret = read(fd, out.as_mut_ptr() as *mut _, out.len());
    if ret < 0 {
        return errno_result();
    }

    Ok(ret as usize)
}

/// Read raw bytes from stdin.
///
/// This will block depending on the underlying mode of stdin. This will ignore the usual lock
/// around stdin that the stdlib usually uses. If other code is using stdin, it is undefined who
/// will get the underlying bytes.
pub fn read_raw_stdin(out: &mut [u8]) -> Result<usize> {
    // Safe because reading from stdin shouldn't have any safety implications.
    unsafe { read_raw(STDIN_FILENO, out) }
}

/// Trait for file descriptors that are TTYs, according to `isatty(3)`.
///
/// # Safety
/// This is marked unsafe because the implementation must promise that the returned RawFd is a valid
/// fd and that the lifetime of the returned fd is at least that of the trait object.
pub unsafe trait Terminal {
    /// Gets the file descriptor of the TTY.
    fn tty_fd(&self) -> RawFd;

    /// Set this terminal's mode to canonical mode (`ICANON | ECHO | ISIG`).
    fn set_canon_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag |= ICANON | ECHO | ISIG)
    }

    /// Set this terminal's mode to raw mode (`!(ICANON | ECHO | ISIG)`).
    fn set_raw_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag &= !(ICANON | ECHO | ISIG))
    }

    /// Sets the non-blocking mode of this terminal's file descriptor.
    ///
    /// If `non_block` is `true`, then `read_raw` will not block. If `non_block` is `false`, then
    /// `read_raw` may block if there is nothing to read.
    fn set_non_block(&self, non_block: bool) -> Result<()> {
        if non_block {
            add_fd_flags(self.tty_fd(), O_NONBLOCK)
        } else {
            clear_fd_flags(self.tty_fd(), O_NONBLOCK)
        }
    }
}

// Safe because we return a genuine terminal fd that never changes and shares our lifetime.
unsafe impl Terminal for Stdin {
    fn tty_fd(&self) -> RawFd {
        STDIN_FILENO
    }
}
