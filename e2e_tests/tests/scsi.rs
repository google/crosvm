// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integration test for scsi devices as virtio-scsi.

use fixture::utils::prepare_disk_img;
use fixture::vm::Config;
use fixture::vm::TestVm;

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
