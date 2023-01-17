// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing vsock.

#![cfg(unix)]

pub mod fixture;

use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use rand::Rng;

use fixture::vm::Config;
use fixture::vm::TestVm;

const HOST_CID: u64 = 2;
const VSOCK_COM_PORT: u64 = 11111;

const SERVER_TIMEOUT_IN_SEC: u64 = 3;
const CLIENT_WAIT_DURATION: Duration = Duration::from_millis(1000);

const MESSAGE_TO_HOST: &str = "Connection from the host is successfully established";
const MESSAGE_TO_GUEST: &str = "Connection from the guest is successfully established";

// generate a random CID to avoid conflicts with other VMs run on different processes
fn generate_guest_cid() -> u32 {
    // avoid special CIDs and negative values
    rand::thread_rng().gen_range(3..0x8000_0000)
}

#[test]
fn host_to_guest() {
    let config = Config::new();
    host_to_guest_connection(config);
}

#[test]
fn host_to_guest_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    host_to_guest_connection(config);
}

fn host_to_guest_connection(config: Config) {
    let guest_cid = generate_guest_cid();
    let config = config.extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    let mut vm = TestVm::new(config).unwrap();

    let handle_guest = thread::spawn(move || {
        let cmd = format!(
            "echo {MESSAGE_TO_HOST} | timeout {SERVER_TIMEOUT_IN_SEC}s ncat -l --vsock {VSOCK_COM_PORT}",
        );
        vm.exec_in_guest(&cmd).unwrap();
    });

    // wait until the server is ready
    thread::sleep(CLIENT_WAIT_DURATION);

    let output = Command::new("ncat")
        .args(["--idle-timeout", "1"])
        .args([
            "--vsock",
            &guest_cid.to_string(),
            &VSOCK_COM_PORT.to_string(),
        ])
        .output()
        .expect("failed to execute process");
    let host_stdout = std::str::from_utf8(&output.stdout).unwrap();

    handle_guest.join().unwrap();

    assert_eq!(host_stdout.trim(), MESSAGE_TO_HOST);
}

#[test]
fn guest_to_host() {
    let config = Config::new();
    guest_to_host_connection(config);
}

#[test]
fn guest_to_host_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    guest_to_host_connection(config);
}

fn guest_to_host_connection(config: Config) {
    let guest_cid = generate_guest_cid();
    let config = config.extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    let mut vm = TestVm::new(config).unwrap();

    let echo = Command::new("echo")
        .arg(MESSAGE_TO_GUEST)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut handle_host = Command::new("timeout")
        .arg(format!("{SERVER_TIMEOUT_IN_SEC}s"))
        .arg("ncat")
        .arg("-l")
        .args(["--vsock", &VSOCK_COM_PORT.to_string()])
        .stdin(echo.stdout.unwrap())
        .spawn()
        .expect("failed to execute process");

    // wait until the server is ready
    thread::sleep(CLIENT_WAIT_DURATION);

    let cmd = format!("ncat --idle-timeout 1 --vsock {HOST_CID} {VSOCK_COM_PORT}");
    let guest_stdout = vm.exec_in_guest(&cmd).unwrap();

    handle_host.wait().unwrap();

    assert_eq!(guest_stdout.trim(), MESSAGE_TO_GUEST);
}
