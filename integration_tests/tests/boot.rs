// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
mod fixture;
use crosvm::Config;
use fixture::{TestVm, TestVmOptions};

#[test]
fn boot_test_vm() {
    let mut vm = TestVm::new(Config::default(), TestVmOptions::default()).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}
