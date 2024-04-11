// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::read_to_string;
use std::num::ParseIntError;
use std::path::Path;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::linux::getpid;
use base::linux::kill;
use base::linux::Signal;
use base::Pid;

/// Stops all the crosvm device processes during moving the guest memory to the staging memory.
///
/// While moving, we must guarantee that no one changes the guest memory contents. This supports
/// devices in sandbox mode only.
///
/// We stop all the crosvm processes instead of the alternatives.
///
/// * Just stop vCPUs
///   * devices still may works in the child process and write something to the guest memory.
/// * Use write protection of userfaultfd
///   * UFFDIO_REGISTER_MODE_WP for shmem is WIP and not supported yet.
/// * `devices::Suspendable::sleep()`
///   * `Suspendable` is not supported by all devices yet.
pub struct ProcessesGuard {
    pids: Vec<Pid>,
}

/// Stops all crosvm child processes except this monitor process using signals.
///
/// The stopped processes are resumed when the freezer object is freed.
///
/// This must be called from the main process.
pub fn freeze_child_processes(monitor_pid: Pid) -> Result<ProcessesGuard> {
    let mut guard = ProcessesGuard {
        pids: load_descendants(getpid(), monitor_pid)?,
    };

    for _ in 0..3 {
        guard.stop_the_world().context("stop the world")?;
        let pids_after = load_descendants(getpid(), monitor_pid)?;
        if pids_after == guard.pids {
            return Ok(guard);
        }
        guard.pids = pids_after;
    }

    bail!("new processes forked while freezing");
}

impl ProcessesGuard {
    /// Stops all the crosvm processes by sending SIGSTOP signal.
    fn stop_the_world(&self) -> Result<()> {
        for pid in &self.pids {
            // SAFETY:
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
        for pid in &self.pids {
            // SAFETY:
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

/// Loads Pids of crosvm descendant processes except the monitor procesess.
fn load_descendants(current_pid: Pid, monitor_pid: Pid) -> Result<Vec<Pid>> {
    // children of the current process.
    let children = read_to_string(format!("/proc/{0}/task/{0}/children", current_pid))
        .context("read children")?;
    let children = children.trim();
    // str::split() to empty string results a iterator just returning 1 empty string.
    if children.is_empty() {
        return Ok(Vec::new());
    }
    let pids: std::result::Result<Vec<i32>, ParseIntError> = children
        .split(" ")
        .map(i32::from_str)
        // except this monitor process
        .filter(|pid| match pid {
            Ok(pid) => *pid != monitor_pid,
            _ => true,
        })
        .collect();
    let pids = pids.context("parse pids")?;
    let mut result = Vec::new();
    for pid in pids {
        result.push(pid);
        let pids = load_descendants(pid, monitor_pid)?;
        result.extend(pids);
    }
    Ok(result)
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

fn wait_for_task_stopped(task_path: &Path) -> Result<()> {
    for _ in 0..10 {
        let stat = read_to_string(task_path.join("stat")).context("read process status")?;
        if let Some(state) = parse_process_state(&stat) {
            if state == 'T' {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(50));
    }
    Err(anyhow!("time out"))
}

fn wait_process_stopped(pid: Pid) -> Result<()> {
    let all_tasks = std::fs::read_dir(format!("/proc/{}/task", pid)).context("read tasks")?;
    for task in all_tasks {
        wait_for_task_stopped(&task.context("read task entry")?.path()).context("wait for task")?;
    }
    Ok(())
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
