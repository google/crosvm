// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-block.

pub mod fixture;

use std::env;
use std::process::Command;

use fixture::Config;
use fixture::TestVm;
use tempfile::NamedTempFile;

const DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;

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

// TODO(b/243127498): Add tests for write and sync operations.
#[test]
fn mount_block() {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap().to_string();
    println!("disk={disk_path}");

    let config = Config::new().extra_args(vec!["--rwdisk".to_string(), disk_path]);
    let mut vm = TestVm::new(config).unwrap();
    assert_eq!(
        vm.exec_in_guest("mount -t ext4 /dev/vdb /mnt && echo 42")
            .unwrap()
            .trim(),
        "42"
    );
}

#[test]
fn resize() {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap().to_string();
    println!("disk={disk_path}");

    let config = Config::new().extra_args(vec!["--rwdisk".to_string(), disk_path]);
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
