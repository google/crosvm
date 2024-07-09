// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-pmem.

#![cfg(any(target_os = "android", target_os = "linux"))]

use fixture::utils::prepare_disk_img;
use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;

/// Tests virtio-pmem device is mountable.
#[test]
fn test_mount_pmem() {
    mount_pmem(VmConfig::new());
}

/// Tests virtio-pmem device is mountable with sandbox disabled.
#[test]
fn test_mount_pmem_disable_sandbox() {
    mount_pmem(VmConfig::new().disable_sandbox());
}

fn mount_pmem(config: VmConfig) {
    let disk = prepare_disk_img();
    let disk_path = disk.path().to_str().unwrap();
    let config = config.extra_args(vec!["--pmem".to_string(), format!("{},ro", disk_path)]);

    let mut vm = TestVm::new(config).unwrap();
    vm.exec_in_guest("mount -t ext4 /dev/pmem0 /mnt")
        .expect("Failed to mount pmem device");
}

/// Tests VMA virtio-pmem to be created successfully with the correct size.
#[test]
fn test_vma_pmem() {
    let vma_size = 1 << 30; // 1GiB
    let config = VmConfig::new().extra_args(vec![
        "--pmem".to_string(),
        format!("vma_pmem,vma-size={},swap-interval-ms=0", vma_size),
    ]);

    let mut vm = TestVm::new(config).unwrap();
    assert_eq!(
        vm.exec_in_guest("blockdev --getsize64 /dev/pmem0")
            .unwrap()
            .stdout
            .trim()
            .parse::<u64>()
            .unwrap(),
        vma_size
    );
}
