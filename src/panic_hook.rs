// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs::File;
use std::io::{stderr, Read};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::panic::{self, PanicInfo};
use std::process::abort;
use std::string::String;

use libc::{close, dup, dup2, pipe2, O_NONBLOCK, STDERR_FILENO};
use sys_util::error;

// Opens a pipe and puts the write end into the stderr FD slot. On success, returns the read end of
// the pipe and the old stderr as a pair of files.
fn redirect_stderr() -> Option<(File, File)> {
    let mut fds = [-1, -1];
    unsafe {
        // Trivially safe because the return value is checked.
        let old_stderr = dup(STDERR_FILENO);
        if old_stderr == -1 {
            return None;
        }
        // Safe because pipe2 will only ever write two integers to our array and we check output.
        let mut ret = pipe2(fds.as_mut_ptr(), O_NONBLOCK);
        if ret != 0 {
            // Leaks FDs, but not important right before abort.
            return None;
        }
        // Safe because the FD we are duplicating is owned by us.
        ret = dup2(fds[1], STDERR_FILENO);
        if ret == -1 {
            // Leaks FDs, but not important right before abort.
            return None;
        }
        // The write end is no longer needed.
        close(fds[1]);
        // Safe because each of the fds was the result of a successful FD creation syscall.
        Some((File::from_raw_fd(fds[0]), File::from_raw_fd(old_stderr)))
    }
}

// Sets stderr to the given file. Returns true on success.
fn restore_stderr(stderr: File) -> bool {
    let fd = stderr.into_raw_fd();

    // Safe because fd is guaranteed to be valid and replacing stderr should be an atomic operation.
    unsafe { dup2(fd, STDERR_FILENO) != -1 }
}

// Sends as much information about the panic as possible to syslog.
fn log_panic_info(default_panic: &(dyn Fn(&PanicInfo) + Sync + Send + 'static), info: &PanicInfo) {
    // Grab a lock of stderr to prevent concurrent threads from trampling on our stderr capturing
    // procedure. The default_panic procedure likely uses stderr.lock as well, but the mutex inside
    // stderr is reentrant, so it will not dead-lock on this thread.
    let stderr = stderr();
    let _stderr_lock = stderr.lock();

    // Redirect stderr to a pipe we can read from later.
    let (mut read_file, old_stderr) = match redirect_stderr() {
        Some(f) => f,
        None => {
            error!("failed to capture stderr during panic");
            return;
        }
    };
    // Only through the default panic handler can we get a stacktrace. It only ever prints to
    // stderr, hence all the previous code to redirect it to a pipe we can read.
    env::set_var("RUST_BACKTRACE", "1");
    default_panic(info);

    // Closes the write end of the pipe so that we can reach EOF in read_to_string. Also allows
    // others to write to stderr without failure.
    if !restore_stderr(old_stderr) {
        error!("failed to restore stderr during panic");
        return;
    }
    drop(_stderr_lock);

    let mut panic_output = String::new();
    // Ignore errors and print what we got.
    let _ = read_file.read_to_string(&mut panic_output);
    // Split by line because the logging facilities do not handle embedded new lines well.
    for line in panic_output.lines() {
        error!("{}", line);
    }
}

/// The intent of our panic hook is to get panic info and a stacktrace into the syslog, even for
/// jailed subprocesses. It will always abort on panic to ensure a minidump is generated.
///
/// Note that jailed processes will usually have a stacktrace of <unknown> because the backtrace
/// routines attempt to open this binary and are unable to do so in a jail.
pub fn set_panic_hook() {
    let default_panic = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        log_panic_info(default_panic.as_ref(), info);
        // Abort to trigger the crash reporter so that a minidump is generated.
        abort();
    }));
}
