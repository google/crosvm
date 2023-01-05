// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

use std::env::current_exe;
use std::process::Command;
use std::thread;
use std::time::Duration;

use base::getpid;
use base::unix::process::fork_process;
use base::AsRawDescriptor;
use base::Tube;
use minijail::Minijail;

/// Tests using fork_process will fail if run inside a multithreaded process. By default, the
/// cargo test harness will use multiple threads to execute tests.
/// To make sure these tests work, we will re-execute the test binary in single threaded mode
/// to execute just the specified test.
fn call_test_in_child_process(name: &str) {
    let result = Command::new(current_exe().unwrap())
        .args([
            "--test-threads=1",
            "--nocapture",
            "--ignored",
            "--exact",
            name,
        ])
        .status()
        .unwrap();
    if !result.success() {
        panic!("Test {name} failed in child process.");
    }
}

#[test]
fn pid_diff() {
    call_test_in_child_process("pid_diff_impl");
}

#[test]
#[ignore = "Only to be called by pid_diff"]
fn pid_diff_impl() {
    let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
    let jail = Minijail::new().unwrap();
    let keep_rds = vec![fork_tube.as_raw_descriptor()];

    let pid = getpid();
    let child = fork_process(jail, keep_rds, None, || {
        // checks that this is a genuine fork with a new PID
        if pid != getpid() {
            fork_tube.send(&1).unwrap()
        } else {
            fork_tube.send(&2).unwrap()
        }
    })
    .expect("failed to fork");

    assert_eq!(tube.recv::<u32>().unwrap(), 1);
    child.wait().unwrap();
}

#[test]
fn thread_name() {
    call_test_in_child_process("thread_name_impl");
}

#[test]
#[ignore = "Only to be called by thread_name"]
fn thread_name_impl() {
    let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
    let jail = Minijail::new().unwrap();
    let keep_rds = vec![fork_tube.as_raw_descriptor()];
    let thread_name = String::from("thread_name");

    let child = fork_process(jail, keep_rds, Some(thread_name.clone()), || {
        fork_tube.send::<u32>(&1).unwrap();
        thread::sleep(Duration::from_secs(10));
    })
    .expect("failed to fork");

    // wait the forked process running.
    tube.recv::<u32>().unwrap();
    let thread_comm =
        std::fs::read_to_string(format!("/proc/{0}/task/{0}/comm", child.pid)).unwrap();

    assert_eq!(thread_comm, thread_name + "\n");

    unsafe { libc::kill(child.pid, libc::SIGKILL) };
    child.wait().unwrap();
}

#[test]
fn thread_name_trimmed() {
    call_test_in_child_process("thread_name_trimmed_impl");
}

#[test]
#[ignore = "Only to be called by thread_name_trimmed"]
fn thread_name_trimmed_impl() {
    let (tube, fork_tube) = Tube::pair().expect("failed to create tube");
    let jail = Minijail::new().unwrap();
    let keep_rds = vec![fork_tube.as_raw_descriptor()];
    let thread_name = String::from("12345678901234567890");

    let child = fork_process(jail, keep_rds, Some(thread_name), || {
        fork_tube.send::<u32>(&1).unwrap();
        thread::sleep(Duration::from_secs(10));
    })
    .expect("failed to fork");

    // wait the forked process running.
    tube.recv::<u32>().unwrap();
    let thread_comm =
        std::fs::read_to_string(format!("/proc/{0}/task/{0}/comm", child.pid)).unwrap();

    assert_eq!(thread_comm, "123456789012345\n");

    unsafe { libc::kill(child.pid, libc::SIGKILL) };
    child.wait().unwrap();
}

#[test]
fn wait_for_success() {
    call_test_in_child_process("wait_for_success_impl");
}

#[test]
#[ignore = "Only to be called by wait_for_success"]
fn wait_for_success_impl() {
    let jail = Minijail::new().unwrap();
    let child = fork_process(jail, vec![], None, || {
        // exit successfully
    })
    .expect("failed to fork");

    assert_eq!(child.wait().unwrap(), 0);
}

#[test]
fn wait_for_panic() {
    call_test_in_child_process("wait_for_panic_impl");
}

#[test]
#[ignore = "Only to be called by wait_for_panic"]
fn wait_for_panic_impl() {
    let jail = Minijail::new().unwrap();
    let child = fork_process(jail, vec![], None, || {
        panic!("fails");
    })
    .expect("failed to fork");

    assert_eq!(child.wait().unwrap(), 101);
}
