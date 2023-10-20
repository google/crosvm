// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration test for scsi devices as virtio-scsi.

use fixture::utils::prepare_disk_img;
use fixture::vm::Config;
use fixture::vm::TestVm;

// Mount the scsi device, and then check if simple read, write, and sync operations work.
fn mount_scsi_device(config: Config) -> anyhow::Result<()> {
    let disk = prepare_disk_img();
    let scsi_disk = disk.path().to_str().unwrap();
    println!("scsi-disk={scsi_disk}");

    let config = config.extra_args(vec!["--scsi-block".to_string(), scsi_disk.to_string()]);
    let mut vm = TestVm::new(config).unwrap();
    vm.exec_in_guest("mount -t ext4 /dev/sda /mnt")?;
    vm.exec_in_guest("echo 42 > /mnt/tmp")?;
    vm.exec_in_guest("sync -d /mnt/tmp")?;
    assert_eq!(vm.exec_in_guest("cat /mnt/tmp")?.stdout.trim(), "42");
    Ok(())
}

#[test]
fn test_scsi_mount() {
    let config = Config::new();
    mount_scsi_device(config).unwrap();
}

#[test]
fn test_scsi_mount_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    mount_scsi_device(config).unwrap();
}

// This test is for commands in controlq.
// First check if the resetting behavior is supported by `sg_opcodes` commands, and then issue the
// `sg_reset` command.
fn reset_scsi(config: Config) -> anyhow::Result<()> {
    let disk = prepare_disk_img();
    let scsi_disk = disk.path().to_str().unwrap();
    let config = config.extra_args(vec!["--scsi-block".to_string(), scsi_disk.to_string()]);
    println!("scsi-disk={scsi_disk}");

    let mut vm = TestVm::new(config).unwrap();
    let cmd = vm.exec_in_guest("sg_opcodes --tmf /dev/sda")?;
    let stdout = cmd.stdout.trim();
    assert!(stdout.contains("Logical unit reset"));
    assert!(stdout.contains("Target reset"));

    assert!(vm.exec_in_guest("sg_reset -d /dev/sda").is_ok());
    Ok(())
}

#[test]
fn test_scsi_reset() {
    let config = Config::new();
    reset_scsi(config).unwrap();
}

#[test]
fn test_scsi_reset_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    reset_scsi(config).unwrap();
}
