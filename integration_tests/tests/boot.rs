// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
mod fixture;
use fixture::TestVm;

#[test]
fn boot_test_vm() {
    let mut vm = TestVm::new(&[], false).unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}

#[test]
fn boot_test_suspend_resume() {
    // There is no easy way for us to check if the VM is actually suspended. But at
    // least exercise the code-path.
    let mut vm = TestVm::new(&[], false).unwrap();
    vm.suspend().unwrap();
    vm.resume().unwrap();
    assert_eq!(vm.exec_in_guest("echo 42").unwrap().trim(), "42");
}
