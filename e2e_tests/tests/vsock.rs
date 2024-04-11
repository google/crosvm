// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing vsock.

#![cfg(any(target_os = "android", target_os = "linux"))]

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
use tempfile::tempdir;
use tempfile::NamedTempFile;

const ANY_CID: &str = "4294967295"; // -1U
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
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new().extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    let mut vm = TestVm::new(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

#[test]
fn host_to_guest_disable_sandbox() {
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec!["--cid".to_string(), guest_cid.to_string()])
        .disable_sandbox();
    let mut vm = TestVm::new(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

#[test]
fn host_to_guest_snapshot_restore() {
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    let mut vm = TestVm::new(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
    let dir = tempdir().unwrap();
    let snap = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap).unwrap();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--restore".to_string(),
            snap.to_str().unwrap().to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    drop(vm);
    vm = TestVm::new_restore(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

#[test]
fn host_to_guest_disable_sandbox_snapshot_restore() {
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    let mut vm = TestVm::new(config.disable_sandbox()).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
    let dir = tempdir().unwrap();
    let snap = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap).unwrap();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--restore".to_string(),
            snap.to_str().unwrap().to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    drop(vm);
    vm = TestVm::new_restore(config.disable_sandbox()).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

fn host_to_guest_connection(vm: &mut TestVm, guest_cid: u32, guest_port: u32) {
    let guest_cmd = vm
        .exec_in_guest_async(&format!(
            "echo {MESSAGE_TO_HOST} | ncat -l --vsock --send-only {ANY_CID} {guest_port}"
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

    guest_cmd.wait_ok(vm).unwrap();
}

#[test]
fn guest_to_host() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new().extra_args(vec!["--cid".to_string(), guest_cid.to_string()]);
    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}

#[test]
fn guest_to_host_disable_sandbox() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec!["--cid".to_string(), guest_cid.to_string()])
        .disable_sandbox();
    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}

#[test]
fn guest_to_host_snapshot_restore() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
    let dir = tempdir().unwrap();
    let snap = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap).unwrap();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
            "--restore".to_string(),
            snap.to_str().unwrap().to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    drop(vm);
    vm = TestVm::new_restore(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}

#[test]
fn guest_to_host_disable_sandbox_snapshot_restore() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console")
        .disable_sandbox();
    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
    let dir = tempdir().unwrap();
    let snap = dir.path().join("snapshot.bkp");
    vm.snapshot(&snap).unwrap();
    let config = Config::new()
        .extra_args(vec![
            "--cid".to_string(),
            guest_cid.to_string(),
            "--no-usb".to_string(),
            "--restore".to_string(),
            snap.to_str().unwrap().to_string(),
        ])
        .with_stdout_hardware("legacy-virtio-console");
    drop(vm);
    vm = TestVm::new_restore(config.disable_sandbox()).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}

fn guest_to_host_connection(vm: &mut TestVm, host_port: u32) {
    let mut host_ncat = Command::new("ncat")
        .arg("-l")
        .arg("--send-only")
        .args(["--vsock", ANY_CID, &host_port.to_string()])
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
    assert_eq!(guest_stdout.stdout.trim(), MESSAGE_TO_GUEST);

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
#[ignore = "b/333090069 test is flaky"]
fn vhost_user_host_to_guest() {
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Device, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user".to_string(),
        format!("vsock,socket={}", socket.path().to_str().unwrap()),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

#[test]
#[ignore = "b/333090069 test is flaky"]
fn vhost_user_host_to_guest_with_devices() {
    let guest_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Devices, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user".to_string(),
        format!("vsock,socket={}", socket.path().to_str().unwrap()),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    host_to_guest_connection(&mut vm, guest_cid, guest_port);
}

#[test]
fn vhost_user_guest_to_host() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Device, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user".to_string(),
        format!("vsock,socket={}", socket.path().to_str().unwrap()),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}

#[test]
fn vhost_user_guest_to_host_with_devices() {
    let host_port = generate_vhost_port();
    let guest_cid = generate_guest_cid();
    let socket = NamedTempFile::new().unwrap();

    let vu_config = create_vu_config(CmdType::Devices, socket.path(), guest_cid);
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = Config::new().extra_args(vec![
        "--vhost-user".to_string(),
        format!("vsock,socket={}", socket.path().to_str().unwrap()),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    guest_to_host_connection(&mut vm, host_port);
}
