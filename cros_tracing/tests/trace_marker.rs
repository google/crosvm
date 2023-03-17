// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::env::current_exe;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::process::Command;

use cros_tracing::*;

const TRACE_FILE: &str = "/sys/kernel/tracing/trace";
const TRACE_CONTEXT_INFO: &str = "/sys/kernel/tracing/options/context-info";
const TRACING_ON: &str = "/sys/kernel/tracing/tracing_on";

fn setup() {
    // Make sure tracing is enabled.
    std::fs::write(TRACING_ON, b"1").unwrap();
    // Remove extra noise from trace file for easier parsing
    std::fs::write(TRACE_CONTEXT_INFO, b"0").unwrap();
    // Clear the trace backlog by writing an empty string, in case we have extra
    // rogue messages in the trace buffer
    std::fs::write(TRACE_FILE, b"").unwrap();

    init();
}

fn cleanup() {
    // Stop tracing.
    std::fs::write(TRACING_ON, b"0").unwrap();
    // Reset trace file format back to how it was.
    std::fs::write(TRACE_CONTEXT_INFO, b"1").unwrap();
}

fn trace_simple_print() {
    let reader = BufReader::new(File::open(TRACE_FILE).ok().unwrap());

    let message1 = "Simple print test one";
    let message2 = "Simple print test two";

    trace_simple_print!("{message1}");
    trace_simple_print!("{message2}");

    // Read contents of the file, skip the first two lines which are just a preamble.
    let mut lines = reader.lines().map(|l| l.unwrap()).skip(2);

    // Check the printed lines are in order.
    // We need to use contains instead of matching the full string because each time we
    // print to trace_marker we will get unique data like PID and timestamps that we cannot
    // rely on, but the contents of the message itself should always contain our string.
    assert!(lines.next().unwrap().contains(message1));
    assert!(lines.next().unwrap().contains(message2));
}

fn push_descriptors() {
    let mut keep_rds = Vec::new();

    push_descriptors!(&mut keep_rds);

    // We cannot know the fd of the trace marker file beforehand but we can check if there
    // is only one fd in the vector it means we can assume it's the trace_marker one.
    assert_eq!(keep_rds.len(), 1);
}

/// Executes the individual test `name` with root, in the same environment as the test suite,
/// if it does not already have root privileges. Sudo needs to be set up to run passwordless
/// or have cached credentials. The parent process spawns a child that runs with higher privileges
/// for that individual `name` test, and then waits for its completion.
///
/// Returns `true` if the test suite already has root privilege, in which case it
/// proceeds to run the test without forking, otherwise it returns `false` to let the
/// test suite know that the test was run by the child process instead.
///
/// # Arguments
///
/// * `name` - Name of the individual test to execute as root
///
/// # Examples
///
/// ```
/// libtest_mimic::Trial::test("test_with_root", move || {
///    if run_test_with_root("test_with_root") {
///        // This part only executes with root
///        function_to_test();
///    }
///    Ok(())
/// });
/// ```
fn run_test_with_root(name: &str) -> bool {
    // This test needs to run as root, so if we aren't root we need to re-execute ourselves
    // with sudo.
    let is_root = match env::var("USER") {
        Ok(val) => val == "root",
        Err(_) => false,
    };

    if !is_root {
        let can_sudo = Command::new("sudo")
            .args(["--askpass", "true"])
            .env("SUDO_ASKPASS", "false")
            .output()
            .unwrap();
        if !can_sudo.status.success() {
            panic!("This test needs to be run as root or with passwordless sudo.");
        }

        let result = Command::new("sudo")
            .args([
                "--preserve-env",
                current_exe().unwrap().to_str().unwrap(),
                "--nocapture",
                "--ignored",
                "--exact",
                name,
            ])
            .status()
            .unwrap();

        if !result.success() {
            panic!("Test {name} forked with root by the trace_marker suite failed.");
        }
        return false;
    }
    true
}

fn main() {
    let args = libtest_mimic::Arguments {
        // Force single-threaded execution to make sure there is no race condition between
        // data written to the trace_marker file. In case the tracefs environment is being
        // used by other processes on the system, these tests might fail.
        test_threads: Some(1),
        ..libtest_mimic::Arguments::from_args()
    };

    let tests = vec![
        libtest_mimic::Trial::test("trace_simple_print", move || {
            if run_test_with_root("trace_simple_print") {
                setup();
                trace_simple_print();
                cleanup();
            }
            Ok(())
        }),
        libtest_mimic::Trial::test("push_descriptors", move || {
            if run_test_with_root("push_descriptors") {
                setup();
                push_descriptors();
                cleanup();
            }
            Ok(())
        }),
    ];
    libtest_mimic::run(&args, tests).exit();
}
