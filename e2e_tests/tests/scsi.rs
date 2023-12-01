// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration test for scsi devices as virtio-scsi.

use std::path::Path;

use fixture::utils::prepare_disk_img;
use fixture::vm::Config;
use fixture::vm::TestVm;

// Mount the scsi device, and then check if simple read, write, and sync operations work.
fn mount_scsi_devices(mut config: Config, count: usize) -> anyhow::Result<()> {
    let disks = (0..count).map(|_| prepare_disk_img()).collect::<Vec<_>>();
    for disk in &disks {
        let scsi_disk = disk.path().to_str().unwrap();
        println!("scsi-disk={scsi_disk}");
        config = config.extra_args(vec!["--scsi-block".to_string(), scsi_disk.to_string()]);
    }

    let mut vm = TestVm::new(config).unwrap();
    for (i, disk) in disks.iter().enumerate() {
        let dev = format!("/dev/sd{}", char::from(b'a' + i as u8));
        let dest = Path::new("/mnt").join(disk.path().file_name().unwrap());
        vm.exec_in_guest("mount -t tmpfs none /mnt")?;
        vm.exec_in_guest(&format!("mkdir -p {}", dest.display()))?;
        vm.exec_in_guest(&format!("mount -t ext4 {dev} {}", dest.display()))?;

        let output = dest.join("tmp");
        vm.exec_in_guest(&format!("echo 42 > {}", output.display()))?;
        vm.exec_in_guest(&format!("sync -d {}", output.display()))?;
        assert_eq!(
            vm.exec_in_guest(&format!("cat {}", output.display()))?
                .stdout
                .trim(),
            "42"
        );
    }
    Ok(())
}

#[test]
fn test_scsi_mount() {
    let config = Config::new();
    mount_scsi_devices(config, 1).unwrap();
}

#[test]
fn test_scsi_mount_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    mount_scsi_devices(config, 1).unwrap();
}

#[test]
fn test_scsi_mount_multi_devices() {
    let config = Config::new();
    mount_scsi_devices(config, 3).unwrap();
}

#[test]
fn test_scsi_mount_multi_devices_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    mount_scsi_devices(config, 3).unwrap();
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

fn write_same_scsi(config: Config) -> anyhow::Result<()> {
    let disk = prepare_disk_img();
    let scsi_disk = disk.path().to_str().unwrap();
    let config = config.extra_args(vec!["--scsi-block".to_string(), scsi_disk.to_string()]);
    println!("scsi-disk={scsi_disk}");

    let mut vm = TestVm::new(config)?;
    assert!(vm
        .exec_in_guest("sg_write_same --16 --lba=0 --num=1 --unmap /dev/sda")
        .is_ok());
    assert!(vm
        .exec_in_guest("sg_write_same --16 --lba=0 --num=1 /dev/sda")
        .is_ok());
    Ok(())
}

#[test]
fn test_scsi_write_same() {
    let config = Config::new();
    write_same_scsi(config).unwrap();
}

#[test]
fn test_scsi_write_same_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    write_same_scsi(config).unwrap();
}

fn unmap_scsi(config: Config) -> anyhow::Result<()> {
    let disk = prepare_disk_img();
    let scsi_disk = disk.path().to_str().unwrap();
    let config = config.extra_args(vec!["--scsi-block".to_string(), scsi_disk.to_string()]);
    println!("scsi-disk={scsi_disk}");

    let mut vm = TestVm::new(config)?;
    assert!(vm
        .exec_in_guest("sg_unmap --lba=0 --num=1 -f /dev/sda")
        .is_ok());
    Ok(())
}

#[test]
fn test_scsi_unmap() {
    let config = Config::new();
    unmap_scsi(config).unwrap();
}

#[test]
fn test_scsi_unmap_disable_sandbox() {
    let config = Config::new().disable_sandbox();
    unmap_scsi(config).unwrap();
}
