// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing vsock.

#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use fixture::utils::retry;
use fixture::utils::ChildExt;
use fixture::utils::CommandExt;
use fixture::vhost_user::CmdType;
use fixture::vhost_user::Config as VuConfig;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config;
use fixture::vm::TestVm;
use rand::Rng;
use tempfile::NamedTempFile;

const HOST_CID: u64 = 2;

const SERVER_TIMEOUT: Duration = Duration::from_secs(3);
const NCAT_RETRIES: usize = 10;

const MESSAGE_TO_HOST: &str = "Connection from the host is successfully established";
const MESSAGE_TO_GUEST: &str = "Connection from the guest is successfully established";

// generate a random CID to avoid conflicts with other VMs run on different processes
fn generate_guest_cid() -> u32 {
    // avoid special CIDs and negative values
    rand::thread_rng().gen_range(3..0x8000_0000)
}

fn generate_vhost_port() -> u32 {
    rand::thread_rng().gen_range(10000..99999)
}

#[test]
fn host_to_guest() {
    let guest_cid = generate_guest_cid();
    let config = Config::new().extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    host_to_guest_connection(config, guest_cid);
}

#[test]
fn host_to_guest_disable_sandbox() {
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec!["--cid".to_string(), guest_cid.to_string()])
        .disable_sandbox();
    host_to_guest_connection(config, guest_cid);
}

fn host_to_guest_connection(config: Config, guest_cid: u32) {
    let guest_port = generate_vhost_port();
    let mut vm = TestVm::new(config).unwrap();

    let guest_cmd = vm
        .exec_in_guest_async(&format!(
            "echo {MESSAGE_TO_HOST} | ncat -l --vsock --send-only {guest_port}"
        ))
        .unwrap();

    let output = retry(
        || {
            Command::new("ncat")
                .args([
                    "--recv-only",
                    "--vsock",
                    &guest_cid.to_string(),
                    &guest_port.to_string(),
                ])
                .stderr(Stdio::inherit())
                .log()
                .output_checked()
        },
        NCAT_RETRIES,
    )
    .unwrap();

    let host_stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(host_stdout.trim(), MESSAGE_TO_HOST);

    guest_cmd.wait(&mut vm).unwrap();
}

#[test]
fn guest_to_host() {
    let guest_cid = generate_guest_cid();
    let config = Config::new().extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    guest_to_host_connection(config);
}

#[test]
fn guest_to_host_disable_sandbox() {
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec!["--cid".to_string(), guest_cid.to_string()])
        .disable_sandbox();
    guest_to_host_connection(config);
}

fn guest_to_host_connection(config: Config) {
    let host_port = generate_vhost_port();
    let mut vm = TestVm::new(config).unwrap();

    let mut host_ncat = Command::new("ncat")
        .arg("-l")
        .arg("--send-only")
        .args(["--vsock", &host_port.to_string()])
        .stdin(Stdio::piped())
        .log()
        .spawn()
        .expect("failed to execute process");

    host_ncat
        .stdin
        .take()
        .unwrap()
        .write_all(MESSAGE_TO_GUEST.as_bytes())
        .unwrap();

    let cmd = format!("ncat --recv-only --vsock {HOST_CID} {host_port}; echo ''");
    let guest_stdout = retry(|| vm.exec_in_guest(&cmd), NCAT_RETRIES).unwrap();
    assert_eq!(guest_stdout.trim(), MESSAGE_TO_GUEST);

    host_ncat.wait_with_timeout(SERVER_TIMEOUT).unwrap();
}

fn create_vu_config(cmd_type: CmdType, socket: &Path, cid: u32) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    println!("cid={cid}, socket={socket_path}");
    match cmd_type {
        CmdType::Device => VuConfig::new(cmd_type, "vsock").extra_args(vec![
            "vsock".to_string(),
            "--socket".to_string(),
            socket_path.to_string(),
            "--cid".to_string(),
            cid.to_string(),
        ]),
        CmdType::Devices => VuConfig::new(cmd_type, "vsock").extra_args(vec![
            "--vsock".to_string(),
            format!("vhost={},cid={}", socket_path, cid),
        ]),
    }
}

#[test]
fn vhost_user_host_to_guest() {
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Device, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user-vsock".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);

    host_to_guest_connection(config, guest_cid);
}

#[test]
fn vhost_user_host_to_guest_with_devices() {
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Devices, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user-vsock".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);

    host_to_guest_connection(config, guest_cid);
}

#[test]
fn vhost_user_guest_to_host() {
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Device, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user-vsock".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);

    guest_to_host_connection(config);
}

#[test]
fn vhost_user_guest_to_host_with_devices() {
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Devices, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user-vsock".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);

    guest_to_host_connection(config);
}
