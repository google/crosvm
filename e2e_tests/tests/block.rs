// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-block.

#![cfg(unix)]

use std::time;

use fixture::utils::create_vu_block_config;
use fixture::utils::prepare_disk_img;
use fixture::utils::DEFAULT_BLOCK_SIZE;
use fixture::vhost_user::CmdType;
use fixture::vhost_user::VhostUserBackend;
use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;
use tempfile::NamedTempFile;

/// Tests virtio-blk device is mountable.
// TODO(b/243127498): Add tests for write and sync operations.
#[test]
fn test_mount_block() {
    let config = VmConfig::new();
    mount_block(config);
}

#[test]
fn test_mount_block_disable_sandbox() {
    let config = VmConfig::new().disable_sandbox();
    mount_block(config);
}

fn mount_block(config: VmConfig) {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap();
    println!("disk={disk_path}");

    let config = config.extra_args(vec!["--block".to_string(), format!("{},ro", disk_path)]);
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
fn test_resize() {
    let config = VmConfig::new();
    resize(config);
}

#[test]
fn test_resize_disable_sandbox() {
    let config = VmConfig::new().disable_sandbox();
    resize(config);
}

fn resize(config: VmConfig) {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap().to_string();
    println!("disk={disk_path}");

    let config = config.extra_args(vec!["--block".to_string(), disk_path]);
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

fn run_vhost_user_test(cmd_type: CmdType, config: VmConfig) {
    let socket = NamedTempFile::new().unwrap();
    let disk = prepare_disk_img();

    let vu_config = create_vu_block_config(cmd_type, socket.path(), disk.path());
    let _vu_device = VhostUserBackend::new(vu_config).unwrap();

    let config = config.extra_args(vec![
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
    let config = VmConfig::new();
    run_vhost_user_test(CmdType::Device, config);
}

/// Tests vhost-user block device with `crosvm devices` (not `device`).
#[test]
fn vhost_user_mount_with_devices() {
    let config = VmConfig::new();
    run_vhost_user_test(CmdType::Devices, config);
}

/// Tests vhost-user block device with `crosvm device`.
#[test]
fn vhost_user_mount_disable_sandbox() {
    let config = VmConfig::new().disable_sandbox();
    run_vhost_user_test(CmdType::Device, config);
}

/// Tests vhost-user block device with `crosvm devices` (not `device`).
#[test]
fn vhost_user_mount_with_devices_disable_sandbox() {
    let config = VmConfig::new().disable_sandbox();
    run_vhost_user_test(CmdType::Devices, config);
}
