// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::read_to_string;
use std::num::ParseIntError;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::unix::getppid;
use base::unix::kill;
use base::unix::Pid;
use base::unix::Signal;

/// Stops all the crosvm processes to take a snapshot.
///
/// While taking a snapshot, we must guarantee that no one changes the guest memory contents. This
/// supports devices in sandbox/non-sandbox mode (running in independent processes/threads in the
/// main process).
///
/// We stop all the crosvm processes instead of the alternatives.
///
/// * Just stop vCPUs
///   * devices still may works in the child process and write something to the guest memory.
/// * Use write protection of userfaultfd
///   * UFFDIO_REGISTER_MODE_WP for shmem is WIP and not supported yet.
pub struct ProcessesGuard {
    pids: Vec<Pid>,
}

/// Stops all crosvm processes except this monitor process using signals.
///
/// The stopped processes are resumed when the freezer object is freed.
pub fn freeze_all_processes() -> Result<ProcessesGuard> {
    let guard = ProcessesGuard {
        pids: load_parent_and_children()?,
    };

    guard.stop_the_world().context("stop the world")?;

    Ok(guard)
}

impl ProcessesGuard {
    /// Stops all the crosvm processes by sending SIGSTOP signal.
    fn stop_the_world(&self) -> Result<()> {
        info!("stop the world");
        for pid in &self.pids {
            // safe because pid in pids are crosvm processes except this monitor process.
            unsafe { kill(*pid, Signal::Stop as i32) }.context("failed to stop process")?;
        }
        for pid in &self.pids {
            wait_process_stopped(*pid).context("wait process stopped")?;
        }
        Ok(())
    }

    /// Resumes all the crosvm processes by sending SIGCONT signal.
    fn continue_the_world(&self) {
        info!("continue the world");
        for pid in &self.pids {
            // safe because pid in pids are crosvm processes except this monitor process and
            // continue signal does not have side effects.
            // ignore the result because we don't care whether it succeeds.
            let _ = unsafe { kill(*pid, Signal::Continue as i32) };
        }
    }
}

impl Drop for ProcessesGuard {
    fn drop(&mut self) {
        self.continue_the_world();
    }
}

/// Loads Pids of crosvm processes except this monitor procesess.
fn load_parent_and_children() -> Result<Vec<Pid>> {
    let monitor_pid = base::getpid();
    // children of the main (parent) process.
    let children = read_to_string(format!("/proc/{0}/task/{0}/children", getppid()))
        .context("read children")?;
    let pids: std::result::Result<Vec<i32>, ParseIntError> = children
        .trim()
        .split(" ")
        .map(i32::from_str)
        // except this monitor process
        .filter(|pid| match pid {
            Ok(pid) => *pid != monitor_pid,
            _ => true,
        })
        .collect();
    let mut pids = pids.context("parse pids")?;
    // add the main (parent) process.
    pids.push(getppid());
    Ok(pids)
}

/// Extract process state from /proc/pid/stat.
///
/// `/proc/<pid>/stat` file contains metadata for the process including the process state.
///
/// See [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) for the format.
fn parse_process_state(text: &str) -> Option<char> {
    let chars = text.chars();
    let mut chars = chars.peekable();
    // skip to the end of "comm"
    while match chars.next() {
        Some(c) => c != ')',
        None => false,
    } {}
    // skip the whitespace between "comm" and "state"
    while match chars.peek() {
        Some(c) => {
            let is_whitespace = *c == ' ';
            if is_whitespace {
                chars.next();
            }
            is_whitespace
        }
        None => false,
    } {}
    // the state
    chars.next()
}

fn wait_process_stopped(pid: Pid) -> Result<()> {
    let process_stat_path = format!("/proc/{}/stat", pid);
    for _ in 0..10 {
        let stat = read_to_string(&process_stat_path).context("read process status")?;
        if let Some(state) = parse_process_state(&stat) {
            if state == 'T' {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(50));
    }
    Err(anyhow!("time out"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_process_state_tests() {
        assert_eq!(parse_process_state("1234 (crosvm) T 0 0 0").unwrap(), 'T');
        assert_eq!(parse_process_state("1234 (crosvm) R 0 0 0").unwrap(), 'R');
        // more than 1 white space
        assert_eq!(parse_process_state("1234 (crosvm)  T 0 0 0").unwrap(), 'T');
        // no white space between comm and state
        assert_eq!(parse_process_state("1234 (crosvm)T 0 0 0").unwrap(), 'T');
        // white space in the comm
        assert_eq!(
            parse_process_state("1234 (crosvm --test) T 0 0 0").unwrap(),
            'T'
        );
        // no status
        assert_eq!(parse_process_state("1234 (crosvm)").is_none(), true);
    }
}
