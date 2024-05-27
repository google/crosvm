// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Testing virtio-pmem.

#![cfg(any(target_os = "android", target_os = "linux"))]

use fixture::vm::Config as VmConfig;
use fixture::vm::TestVm;

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
