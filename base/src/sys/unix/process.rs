// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides [fork_process] to fork a process.

#![deny(missing_docs)]

use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::os::unix::process::ExitStatusExt;
use std::process;

use log::warn;
use minijail::Minijail;

use crate::error;
use crate::unix::wait_for_pid;
use crate::unix::Pid;
use crate::RawDescriptor;

/// Child represents the forked process.
pub struct Child {
    /// The pid of the child process.
    pub pid: Pid,
}

impl Child {
    /// Wait for the child process exit using `waitpid(2)`.
    pub fn wait(self) -> crate::Result<u8> {
        // Suppress warning from the drop().
        let pid = self.into_pid();
        let (_, status) = wait_for_pid(pid, 0)?;
        if let Some(exit_code) = status.code() {
            Ok(exit_code as u8)
        } else if let Some(signal) = status.signal() {
            let exit_code = if signal as i32 >= 128 {
                warn!("wait for child: unexpected signal({:?})", signal);
                255
            } else {
                128 + signal as u8
            };
            Ok(exit_code)
        } else {
            unreachable!("waitpid with option 0 only waits for exited and signaled status");
        }
    }

    /// Convert [Child] into [Pid].
    ///
    /// If [Child] is dropped without `Child::wait()`, it logs warning message. Users who wait
    /// processes in other ways should suppress the warning by unwrapping [Child] into [Pid].
    ///
    /// The caller of this method now owns the process and is responsible for managing the
    /// termination of the process.
    pub fn into_pid(self) -> Pid {
        let pid = self.pid;
        // Suppress warning from the drop().
        let _ = ManuallyDrop::new(self);
        pid
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        warn!("the child process have not been waited.");
    }
}

/// Forks this process using [Minijail] and calls a closure in the new process.
///
/// After `post_fork_cb` returns, the new process exits with `0` code. If `post_fork_cb` panics, the
/// new process exits with `101` code.
///
/// This function never returns in the forked process.
///
/// # Arguments
///
/// * `jail` - [Minijail] instance to fork.
/// * `keep_rds` - [RawDescriptor]s to be kept in the forked process. other file descriptors will be
///   closed by [Minijail] in the forked process.
/// * `debug_label` - (optional) thread name. this will be trimmed to 15 charactors.
/// * `post_fork_cb` - Callback to run in the new process.
pub fn fork_process<F>(
    jail: Minijail,
    mut keep_rds: Vec<RawDescriptor>,
    debug_label: Option<String>,
    post_fork_cb: F,
) -> minijail::Result<Child>
where
    F: FnOnce(),
{
    // Deduplicate the FDs since minijail expects this.
    keep_rds.sort_unstable();
    keep_rds.dedup();

    let tz = std::env::var("TZ").unwrap_or_default();

    // Safe because the program is still single threaded.
    // We own the jail object and nobody else will try to reuse it.
    let pid = match unsafe { jail.fork(Some(&keep_rds)) }? {
        0 => {
            struct ExitGuard;
            impl Drop for ExitGuard {
                fn drop(&mut self) {
                    // Rust exits with 101 when panics.
                    process::exit(101);
                }
            }
            // Prevents a panic in post_fork_cb from bypassing the process::exit.
            let _exit_guard = ExitGuard {};

            if let Some(debug_label) = debug_label {
                // pthread_setname_np() limit on Linux
                const MAX_THREAD_LABEL_LEN: usize = 15;
                let debug_label_trimmed = &debug_label.as_bytes()
                    [..std::cmp::min(MAX_THREAD_LABEL_LEN, debug_label.len())];
                match CString::new(debug_label_trimmed) {
                    Ok(thread_name) => {
                        // Safe because thread_name is a valid pointer and setting name of this
                        // thread should be safe.
                        let _ = unsafe {
                            libc::pthread_setname_np(libc::pthread_self(), thread_name.as_ptr())
                        };
                    }
                    Err(e) => {
                        error!("failed to compile thread name: {:?}", e);
                    }
                }
            }

            // Preserve TZ for `chrono::Local` (b/257987535).
            std::env::set_var("TZ", tz);

            post_fork_cb();
            // ! Never returns
            process::exit(0);
        }
        pid => pid,
    };
    Ok(Child { pid })
}
