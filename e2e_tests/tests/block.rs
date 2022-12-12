// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-block.

#![cfg(unix)]

pub mod fixture;

use std::env;
use std::path::Path;
use std::process::Command;
use std::time;

use fixture::vhost_user::CmdType;
use fixture::vhost_user::Config as VuConfig;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;
use tempfile::NamedTempFile;

const DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;

/// Prepare a temporary ext4 disk file.
fn prepare_disk_img() -> NamedTempFile {
    let mut disk = NamedTempFile::new().unwrap();
    disk.as_file_mut().set_len(DEFAULT_BLOCK_SIZE).unwrap();

    // Add /sbin and /usr/sbin to PATH since some distributions put mkfs.ext4 in one of those
    // directories but don't add them to non-root PATH.
    let path = env::var("PATH").unwrap();
    let path = [&path, "/sbin", "/usr/sbin"].join(":");

    // TODO(b/243127910): Use `mkfs.ext4 -d` to include test data.
    Command::new("mkfs.ext4")
        .arg(disk.path().to_str().unwrap())
        .env("PATH", path)
        .output()
        .expect("failed to execute process");
    disk
}

/// Tests virtio-blk device is mountable.
// TODO(b/243127498): Add tests for write and sync operations.
#[test]
fn mount_block() {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap();
    println!("disk={disk_path}");

    let config =
        VmConfig::new().extra_args(vec!["--block".to_string(), format!("{},ro", disk_path)]);
    let mut vm = TestVm::new(config).unwrap();
    assert_eq!(
        vm.exec_in_guest("mount -t ext4 /dev/vdb /mnt && echo 42")
            .unwrap()
            .trim(),
        "42"
    );
}

/// Tests `crosvm disk resize` works.
#[test]
fn resize() {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap().to_string();
    println!("disk={disk_path}");

    let config = VmConfig::new().extra_args(vec!["--block".to_string(), disk_path]);
    let mut vm = TestVm::new(config).unwrap();

    // Check the initial block device size.
    assert_eq!(
        vm.exec_in_guest("blockdev --getsize64 /dev/vdb")
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap(),
        DEFAULT_BLOCK_SIZE
    );

    let new_size = DEFAULT_BLOCK_SIZE * 2;

    // The index of the disk to resize.
    let disk_index = 1;

    vm.disk(vec![
        "resize".to_string(),
        disk_index.to_string(),
        new_size.to_string(),
    ])
    .expect("Disk resizing command failed");

    // Allow block device size to be updated within 500ms
    let now = time::Instant::now();

    while now.elapsed() <= time::Duration::from_millis(500) {
        if vm
            .exec_in_guest("blockdev --getsize64 /dev/vdb")
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap()
            == new_size
        {
            return;
        }
    }
    // Check the new block device size.
    assert_eq!(
        vm.exec_in_guest("blockdev --getsize64 /dev/vdb")
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap(),
        new_size
    );
}

fn create_vu_config(cmd_type: CmdType, socket: &Path, disk: &Path) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    let disk_path = disk.to_str().unwrap();
    println!("disk={disk_path}, socket={socket_path}");
    match cmd_type {
        CmdType::Device => VuConfig::new(cmd_type, "block").extra_args(vec![
            "block".to_string(),
            "--socket".to_string(),
            socket_path.to_string(),
            "--file".to_string(),
            disk_path.to_string(),
        ]),
        CmdType::Devices => VuConfig::new(cmd_type, "block").extra_args(vec![
            "--block".to_string(),
            format!("vhost={},path={}", socket_path, disk_path),
        ]),
    }
}

fn run_vhost_user_test(cmd_type: CmdType) {
    let socket = NamedTempFile::new().unwrap();
    let disk = prepare_disk_img();

    let vu_config = create_vu_config(cmd_type, socket.path(), disk.path());
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = VmConfig::new().extra_args(vec![
        "--vhost-user-blk".to_string(),
        socket.path().to_str().unwrap().to_string(),
    ]);
    let mut vm = TestVm::new(config).unwrap();
    assert_eq!(
        vm.exec_in_guest("mount -t ext4 /dev/vdb /mnt && echo 42")
            .unwrap()
            .trim(),
        "42"
    );
}

/// Tests vhost-user block device with `crosvm device`.
#[test]
fn vhost_user_mount() {
    run_vhost_user_test(CmdType::Device);
}

/// Tests vhost-user block device with `crosvm devices` (not `device`).
#[test]
fn vhost_user_mount_with_devices() {
    run_vhost_user_test(CmdType::Devices);
}
